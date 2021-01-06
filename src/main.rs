use regex::Regex;
use std::io;

use serde_derive::{Deserialize, Serialize};

use log::{debug, error};

use actix::prelude::Addr;
use actix::Actor;
use actix_web::client::Client;
use actix_web::web::Data;
use actix_web::*;

use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;

use lazy_static::lazy_static;
use rand::seq::IteratorRandom;
use rand::thread_rng;

use std::sync::Arc;

mod otp;

use otp::{OtpError, OtpValidator};

mod settings;

use settings::Settings;

mod actors;

use actors::{CacheOrIgnoreOtp, DuplicateMessagesActor, RemoveOtp};

static EXIT_FAILURE: i32 = 1;

static SLACK_POST_MESSAGE_ENDPOINT: &str = "https://slack.com/api/chat.postMessage";
lazy_static! {
    static ref SUCCESS_TEXT: String = String::from("OTP validated");
}
lazy_static! {
    static ref REPLAYED_TEXT: String = String::from("Replayed OTP");
}

lazy_static! {
    static ref START_END_OTP_RE: Regex = Regex::new("(.{4,4}).+(.{4,4})$").unwrap();
}

struct ValidatorApp {
    validator: otp::OtpValidator,
    slack_bot_token: String,
    slack_signing_secret: String,
    success: Vec<String>,
    replayed: Vec<String>,
    success_explanation: String,
    replayed_explanation: String,
    duplicate_messages_actor: Addr<DuplicateMessagesActor>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Event {
    Chal(Challenge),
    Msg(Box<OuterEvent>),
}

#[derive(Debug, Deserialize)]
struct Challenge {
    token: String,
    challenge: String,
    #[serde(rename = "type")]
    event_type: String,
}

#[derive(Debug, Deserialize)]
struct Message {
    #[serde(rename = "type")]
    event_type: String,
    channel: String,
    user: String,
    text: String,
    ts: String,
    thread_ts: Option<String>,
    event_ts: String,
    channel_type: String,
    client_msg_id: String,
}

#[derive(Debug, Deserialize)]
struct OuterEvent {
    token: String,
    team_id: String,
    api_app_id: String,
    event: Message,
    #[serde(rename = "type")]
    event_type: String,
    authed_users: Vec<String>,
    event_id: String,
    event_time: u64,
}

#[derive(Debug, Serialize)]
struct ChallengeResponse {
    challenge: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum Response {
    Chal(ChallengeResponse),
}

type HmacSha256 = Hmac<Sha256>;

fn slack_escape_text(text: &str) -> String {
    // Escape text as required by https://api.slack.com/docs/message-formatting#how_to_escape_characters
    let mut s = String::with_capacity(2 * text.len());

    for c in text.chars() {
        match c {
            '<' => s.push_str("&lt;"),
            '>' => s.push_str("&gt;"),
            '&' => s.push_str("&amp;"),
            _ => s.push(c),
        };
    }

    s
}

/// Shortens an OTP to its first and last four letters with dots in between.
/// It assumes the `otp` parameter is a valid OTP (44 characters long).
fn shorten_otp(otp: &str) -> String {
    let mut ret = String::with_capacity(13);

    let caps = START_END_OTP_RE.captures(otp).unwrap();
    ret.push_str(&caps.get(1).unwrap().as_str());
    ret.push_str("...");
    ret.push_str(&caps.get(2).unwrap().as_str());

    ret
}

/// Replaces the special dollar syntax and escapes the message
fn prepare_slack_message(text: &str, otp: &str, user: &str) -> String {
    slack_escape_text(&text.replace("$o", otp).replace("$O", &shorten_otp(otp)))
        .replace("$u", &format!("<@{}>", user))
}

/// Verifies the signature of the data received by Slack
fn verify_signature(
    ts: Option<&http::HeaderValue>,
    sig: Option<&http::HeaderValue>,
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

    let mut hmac = HmacSha256::new_varkey(signing_secret.as_bytes()).expect("Key length not valid");
    hmac.update(b"v0:");
    hmac.update(req_timestamp.as_bytes());
    hmac.update(b":");
    hmac.update(&bytes);

    if hmac.verify(&req_signature).is_err() {
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

    let event = serde_json::from_slice::<Event>(&bytes)?;

    match event {
        Event::Chal(c) => Ok(HttpResponse::Ok().json(Response::Chal(ChallengeResponse {
            challenge: c.challenge,
        }))),

        Event::Msg(m) => {
            let mut otp = match otp::extract_otp(&m.event.text) {
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
            let mut rng = thread_rng();
            let text;
            let explanation;
            match decrypted_otp {
                Ok(_) => {
                    text = s.success.iter().choose(&mut rng).unwrap_or(&SUCCESS_TEXT);
                    explanation = &s.success_explanation;
                }
                Err(OtpError::ReplayedOtp) => {
                    text = s.replayed.iter().choose(&mut rng).unwrap_or(&REPLAYED_TEXT);
                    explanation = &s.replayed_explanation;
                }
                Err(e) => {
                    return Err(actix_web::error::ErrorBadRequest(e));
                }
            }

            let esc_text = prepare_slack_message(text, &otp, &m.event.user);
            let explanation = prepare_slack_message(&explanation, &otp, &m.event.user);

            let reply = serde_json::json!({
                "channel": m.event.channel,
                "thread_ts": m.event.thread_ts,
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

            client
                .post(SLACK_POST_MESSAGE_ENDPOINT)
                .header("Content-Type", "application/json; charset=UTF-8")
                .header("Authorization", tok)
                .send_json(&reply)
                .await?;

            let remove_resp = s.duplicate_messages_actor.send(RemoveOtp(otp)).await;
            match remove_resp {
                Err(_) => Err(actix_web::error::ErrorInternalServerError(
                    "Internal server error",
                )),
                Ok(_) => Ok(HttpResponse::Ok().finish()),
            }
        }
    }
}

#[actix_rt::main]
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

    let api_key = if let Ok(key) = base64::decode(&settings.otpvalidation.apikey) {
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

    let dup = DuplicateMessagesActor::new().start();

    let vapp = Arc::new(ValidatorApp {
        validator,
        slack_bot_token: settings.slack.bottoken,
        slack_signing_secret: settings.slack.signingsecret,
        success: settings.answers.success,
        replayed: settings.answers.replayed,
        success_explanation: settings.explanation.success,
        replayed_explanation: settings.explanation.replayed,
        duplicate_messages_actor: dup,
    });

    HttpServer::new(move || {
        App::new()
            .data(Arc::clone(&vapp))
            .wrap(middleware::Logger::default())
            .service(web::resource("/").route(web::post().to(handle_req)))
            .service(
                web::resource("/health").route(web::get().to(|| HttpResponse::Ok().body("OK"))),
            )
    })
    .bind(format!("{}:{}", address, port))?
    .run()
    .await
}
