use base64::Engine;
use regex::Regex;
use std::io;

use log::{debug, error};

use actix::prelude::Addr;
use actix::Actor;
use actix_web::http::header::HeaderValue;
use actix_web::web::Data;
use actix_web::*;
use awc::Client;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use std::sync::Arc;
use std::sync::LazyLock;

mod otp;

use otp::{OtpError, OtpValidator};

mod settings;

use settings::{CounterThresholds, Settings};

mod actors;

use actors::{
    BotResponsesActor, CacheOrIgnoreOtp, DuplicateMessagesActor, NewBotMessage, NewReply,
    RemoveOtp, RepliesSelectionActor, Reply, RetrieveBotMessageInfo,
};

mod slack;

use slack::{ChallengeResponse, Event, Message, PostMessageResponse, Response};

static EXIT_FAILURE: i32 = 1;

static SLACK_POST_MESSAGE_ENDPOINT: &str = "https://slack.com/api/chat.postMessage";

static START_END_OTP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("(.{4,4}).+(.{4,4})$").unwrap());

struct ValidatorApp {
    validator: otp::OtpValidator,
    slack_bot_token: String,
    slack_signing_secret: String,
    success_explanation: String,
    replayed_explanation: String,
    duplicate_messages_actor: Addr<DuplicateMessagesActor>,
    bot_responses_actor: Addr<BotResponsesActor>,
    replies_actor: Addr<RepliesSelectionActor>,
    counter_thresholds: CounterThresholds,
}

type HmacSha256 = Hmac<Sha256>;

/// Shortens an OTP to its first and last four letters with dots in between.
/// It assumes the `otp` parameter is a valid OTP (44 characters long).
fn shorten_otp(otp: &str) -> String {
    let mut ret = String::with_capacity(13);

    let caps = START_END_OTP_RE.captures(otp).unwrap();
    ret.push_str(caps.get(1).unwrap().as_str());
    ret.push_str("...");
    ret.push_str(caps.get(2).unwrap().as_str());

    ret
}

/// Replaces the special dollar syntax and escapes the message
fn prepare_slack_message(text: &str, otp: &str, user: &str) -> String {
    slack::slack_escape_text(&text.replace("$o", otp).replace("$O", &shorten_otp(otp)))
        .replace("$u", &format!("<@{}>", user))
}

/// Verifies the signature of the data received by Slack
fn verify_signature(
    ts: Option<&HeaderValue>,
    sig: Option<&HeaderValue>,
    signing_secret: &str,
    bytes: &web::Bytes,
) -> bool {
    let req_timestamp = if let Some(timestamp) = ts {
        timestamp
    } else {
        debug!("Unable to extract timestamp header");
        return false;
    };

    let req_signature = if let Some(signature) = sig {
        signature
    } else {
        debug!("Unable to extract signature header");
        return false;
    };

    let req_signature = if let Ok(s) = req_signature.to_str() {
        s
    } else {
        debug!("Unable to convert signature header to string");
        return false;
    };

    if !req_signature.starts_with("v0=") {
        debug!("Malformed Slack signature");
        return false;
    }

    let req_signature = if let Ok(sig) = hex::decode(&req_signature[3..]) {
        sig
    } else {
        debug!("Non decodable hex string in signature header");
        return false;
    };

    let mut hmac = HmacSha256::new_from_slice(signing_secret.as_bytes())
        .expect("This should never fail for Hmac");
    hmac.update(b"v0:");
    hmac.update(req_timestamp.as_bytes());
    hmac.update(b":");
    hmac.update(bytes);

    if hmac.verify_slice(&req_signature).is_err() {
        debug!("Wrong Slack signature");
        false
    } else {
        true
    }
}

async fn handle_req(
    bytes: web::Bytes,
    req: HttpRequest,
    s: Data<Arc<ValidatorApp>>,
) -> Result<HttpResponse, Error> {
    let headers = req.headers().clone();

    let signing_secret = &s.slack_signing_secret.to_owned();

    if cfg!(debug_assertions) {
        debug!("Debug mode, skipping signature check");
    } else if !verify_signature(
        headers.get("X-Slack-Request-Timestamp"),
        headers.get("X-Slack-Signature"),
        signing_secret,
        &bytes,
    ) {
        return Ok(HttpResponse::Ok().finish());
    }

    let event = if let Ok(ev) = serde_json::from_slice::<Event>(&bytes) {
        ev
    } else {
        // We don't know how to handle this message, but if we send an error
        // to Slack they will retry.
        debug!("Dropping unknown message type");
        return Ok(HttpResponse::Ok().finish());
    };

    match event {
        Event::Chal(c) => Ok(HttpResponse::Ok().json(Response::Chal(ChallengeResponse {
            challenge: c.challenge,
        }))),

        Event::Msg(message) => {
            match message.event {
                Message::Simple(m) => {
                    let mut otp = match otp::extract_otp(&m.text) {
                        Some(otp) => otp,
                        None => {
                            return Ok(HttpResponse::Ok().finish());
                        }
                    };

                    debug!("Found otp: {:?}", otp);
                    if otp.len() == 43 && (otp.starts_with('c') || otp.starts_with('j')) {
                        let c = otp.chars().next().unwrap(); // unwrap is fine, we know it's there.
                        otp.insert(0, c);
                        debug!("Otp received is 43 chars long, prepending '{}'", c);
                    }

                    // If we don't reply to Slack in 3 seconds, they'll retry the message
                    // and we'll validate the OTP again and send multiple replies to
                    // Slack. So we keep a cache around and just return if the OTP
                    // we see is in the process of being validated. It'll be removed
                    // from the map right after producing a reply to Slack.
                    let cache_resp = s
                        .duplicate_messages_actor
                        .send(CacheOrIgnoreOtp(otp.to_owned()))
                        .await;
                    if let Ok(stored) = cache_resp {
                        if !stored {
                            debug!("Otp {} received again while still validating", otp);
                            return Ok(HttpResponse::Ok().finish());
                        }
                    } else {
                        return Err(actix_web::error::ErrorInternalServerError(
                            "Internal server error",
                        ));
                    }

                    let tok = format!("Bearer {}", &s.slack_bot_token);

                    let decrypted_otp = s.validator.validate_otp(&otp).await?;

                    debug!("Decrypted OTP: {:?}", decrypted_otp);
                    let text;
                    let explanation;
                    match decrypted_otp {
                        Ok(otp) => {
                            let thresholds = s.counter_thresholds;
                            let reply = if otp.is_new_device(thresholds.ctr, thresholds.usage) {
                                s.replies_actor.send(NewReply {
                                    reply_type: Reply::SuccessNewDevice,
                                })
                            } else {
                                s.replies_actor.send(NewReply {
                                    reply_type: Reply::Success,
                                })
                            }
                            .await;

                            if let Ok(r) = reply {
                                text = r;
                            } else {
                                return Err(actix_web::error::ErrorInternalServerError(
                                    "Internal server error",
                                ));
                            }

                            explanation = &s.success_explanation;
                        }
                        Err(OtpError::ReplayedOtp) => {
                            let reply = s
                                .replies_actor
                                .send(NewReply {
                                    reply_type: Reply::Replayed,
                                })
                                .await;
                            if let Ok(r) = reply {
                                text = r;
                            } else {
                                return Err(actix_web::error::ErrorInternalServerError(
                                    "Internal server error",
                                ));
                            }

                            explanation = &s.replayed_explanation;
                        }
                        Err(e) => {
                            return Err(actix_web::error::ErrorBadRequest(e));
                        }
                    }

                    let esc_text = prepare_slack_message(&text, &otp, &m.user);
                    let explanation = prepare_slack_message(explanation, &otp, &m.user);

                    let reply = serde_json::json!({
                        "channel": m.channel,
                        "thread_ts": m.thread_ts,
                        "text": esc_text,
                        "blocks": [
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": esc_text
                                }
                            },
                            {
                                "type": "context",
                                "elements": [
                                    {
                                        "type": "mrkdwn",
                                        "text": &explanation
                                    }
                                ]
                            }
                        ]
                    });

                    let client = Client::default();

                    let response = client
                        .post(SLACK_POST_MESSAGE_ENDPOINT)
                        .append_header(("Content-Type", "application/json; charset=UTF-8"))
                        .append_header(("Authorization", tok))
                        .send_json(&reply)
                        .await;

                    if response.is_err() {
                        return Err(actix_web::error::ErrorInternalServerError(
                            "Internal server error",
                        ));
                    }

                    let response_body = match response.unwrap().body().await {
                        Ok(resp) => resp,
                        Err(err) => return Err(actix_web::error::ErrorInternalServerError(err)),
                    };
                    let post_message_response =
                        serde_json::from_slice::<PostMessageResponse>(&response_body)?;

                    let new_message_resp = s
                        .bot_responses_actor
                        .send(NewBotMessage::new(m.ts, post_message_response))
                        .await;

                    if new_message_resp.is_err() {
                        return Err(actix_web::error::ErrorInternalServerError(
                            "Internal server error",
                        ));
                    }

                    let remove_resp = s.duplicate_messages_actor.send(RemoveOtp(otp)).await;
                    match remove_resp {
                        Err(_) => Err(actix_web::error::ErrorInternalServerError(
                            "Internal server error",
                        )),
                        Ok(_) => Ok(HttpResponse::Ok().finish()),
                    }
                }
                Message::Bot(_) => Ok(HttpResponse::Ok().finish()),
                Message::Deleted(m) => {
                    let bot_message_response = s
                        .bot_responses_actor
                        .send(RetrieveBotMessageInfo(m.deleted_ts))
                        .await;
                    let bot_message_info: PostMessageResponse =
                        if let Ok(maybe_bot_message) = bot_message_response {
                            match maybe_bot_message {
                                Some(bot_message_info) => bot_message_info,
                                None => return Ok(HttpResponse::Ok().finish()),
                            }
                        } else {
                            return Err(actix_web::error::ErrorInternalServerError(
                                "Internal server error",
                            ));
                        };

                    let client = Client::default();
                    let tok = format!("Bearer {}", &s.slack_bot_token);

                    let text;
                    let reply = s
                        .replies_actor
                        .send(NewReply {
                            reply_type: Reply::Deleted,
                        })
                        .await;
                    if let Ok(r) = reply {
                        text = r;
                    } else {
                        return Err(actix_web::error::ErrorInternalServerError(
                            "Internal server error",
                        ));
                    }

                    let reply = serde_json::json!({
                        "channel": bot_message_info.channel,
                        "thread_ts": bot_message_info.ts,
                        "text": slack::slack_escape_text(&text),
                    });

                    let res = client
                        .post(SLACK_POST_MESSAGE_ENDPOINT)
                        .append_header(("Content-Type", "application/json; charset=UTF-8"))
                        .append_header(("Authorization", tok))
                        .send_json(&reply)
                        .await;

                    if res.is_err() {
                        return Err(actix_web::error::ErrorInternalServerError(
                            "Internal server error",
                        ));
                    }

                    Ok(HttpResponse::Ok().finish())
                }
            }
        }
    }
}

async fn handle_health() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().body("OK"))
}

#[actix_web::main]
async fn main() -> Result<(), io::Error> {
    env_logger::Builder::from_env("YUBOTP_LOG").init();

    let settings = match Settings::new(
        &std::env::var("YUBOTP_CFG").unwrap_or_else(|_| "config.toml".to_owned()),
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("Unable to start, configuration error: {}", e);
            std::process::exit(EXIT_FAILURE);
        }
    };

    debug!("{}", settings);

    let api_key = if let Ok(key) =
        base64::engine::general_purpose::STANDARD.decode(&settings.otpvalidation.apikey)
    {
        key
    } else {
        error!("API key is not valid base64");
        std::process::exit(EXIT_FAILURE)
    };

    let validator = OtpValidator::new(
        settings.otpvalidation.clientid,
        api_key,
        settings.otpvalidation.apihost,
    );

    let address = &settings.server.address;
    let port = settings.server.port;

    let counter_thresholds = settings.counterthresholds;

    let dup = DuplicateMessagesActor::new().start();
    let bot_resp = BotResponsesActor::new().start();
    let replies = RepliesSelectionActor::new(
        settings.answers.newdevice,
        settings.answers.success,
        settings.answers.replayed,
        settings.answers.deleted,
    )
    .start();

    let vapp = Arc::new(ValidatorApp {
        validator,
        slack_bot_token: settings.slack.bottoken,
        slack_signing_secret: settings.slack.signingsecret,
        success_explanation: settings.explanation.success,
        replayed_explanation: settings.explanation.replayed,
        duplicate_messages_actor: dup,
        bot_responses_actor: bot_resp,
        replies_actor: replies,
        counter_thresholds,
    });

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(Arc::clone(&vapp)))
            .wrap(middleware::Logger::default())
            .service(web::resource("/").route(web::post().to(handle_req)))
            .service(web::resource("/health").route(web::get().to(handle_health)))
    })
    .bind(format!("{}:{}", address, port))?
    .run()
    .await
}
