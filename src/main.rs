use std::io;

use serde_derive::{Deserialize, Serialize};
use serde_json;

use log::{debug, error};

use actix_web::client::Client;
use actix_web::error::ErrorBadRequest;
use actix_web::web::Data;
use actix_web::*;
use futures::Future;

use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha2::Sha256;

use lazy_static::lazy_static;
use rand::{thread_rng, Rng};

use hex;

use std::sync::Arc;

mod otp;

use otp::{OtpError, OtpValidator};

mod settings;

use settings::Settings;

static EXIT_FAILURE: i32 = 1;

static SLACK_POST_MESSAGE_ENDPOINT: &str = "https://slack.com/api/chat.postMessage";
lazy_static! {
    static ref SUCCESS_TEXT: String = String::from("OTP validated");
}
lazy_static! {
    static ref REPLAYED_TEXT: String = String::from("Replayed OTP");
}

struct ValidatorApp {
    validator: otp::OtpValidator,
    slack_bot_token: String,
    slack_signing_secret: String,
    success: Vec<String>,
    replayed: Vec<String>,
    success_explanation: String,
    replayed_explanation: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Event {
    Chal(Challenge),
    Msg(OuterEvent),
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

fn slack_escape_text(text: &String) -> String {
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

fn into_box_dyn<T>(e: Result<T, Error>) -> Box<dyn Future<Item = T, Error = Error>>
where
    T: 'static,
{
    Box::new(futures::future::result(e))
}

fn parse_from_json(data: &[u8]) -> Result<Event, Error> {
    serde_json::from_slice(data).map_err(ErrorBadRequest)
}

fn handle_req(
    bytes: web::Bytes,
    req: HttpRequest,
    s: Data<Arc<ValidatorApp>>,
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let headers = req.headers().clone();

    let signing_secret = &s.slack_signing_secret.to_owned();

    if cfg!(debug_assertions) {
        debug!("Debug mode, skipping signature check");
    } else {
        let req_timestamp = match headers.get("X-Slack-Request-Timestamp") {
            Some(header) => header,
            None => {
                debug!("Unable to extract timestamp header");
                return into_box_dyn(Ok(HttpResponse::Ok().finish()));
            }
        };
        let req_signature = match headers.get("X-Slack-Signature") {
            Some(header) => header,
            None => {
                debug!("Unable to extract signature header");
                return into_box_dyn(Ok(HttpResponse::Ok().finish()));
            }
        };

        let req_signature = match req_signature.to_str() {
            Ok(s) => s,
            Err(_) => {
                debug!("Unable to convert signature header to string");
                return into_box_dyn(Ok(HttpResponse::Ok().finish()));
            }
        };

        if !req_signature.starts_with("v0=") {
            debug!("Malformed Slack signature");
            return into_box_dyn(Ok(HttpResponse::Ok().finish()));
        }

        let req_signature = if let Ok(sig) = hex::decode(&req_signature[3..]) {
            sig
        } else {
            debug!("Non decodable hex string in signature header");
            return into_box_dyn(Ok(HttpResponse::Ok().finish()));
        };

        let mut hmac = Hmac::new(Sha256::new(), signing_secret.as_bytes());
        hmac.input(b"v0:");
        hmac.input(req_timestamp.as_bytes());
        hmac.input(b":");
        hmac.input(&bytes);

        let res = hmac.result();
        if res.code() != &*req_signature {
            debug!("Wrong Slack signature");
            return into_box_dyn(Ok(HttpResponse::Ok().finish()));
        }
    }

    let f =
        futures::future::result(parse_from_json(&bytes)).and_then(
            move |event: Event| match event {
                Event::Chal(c) => into_box_dyn(Ok(HttpResponse::Ok().json(Response::Chal(
                    ChallengeResponse {
                        challenge: c.challenge,
                    },
                )))),

                Event::Msg(m) => {
                    let mut otp = match otp::extract_otp(&m.event.text) {
                        Some(otp) => otp,
                        None => {
                            return into_box_dyn(Ok(HttpResponse::Ok().finish()));
                        }
                    };

                    debug!("Found otp: {:?}", otp);
                    if otp.len() == 43 && otp.starts_with('c') {
                        otp.insert(0, 'c');
                        debug!("Otp received is 43 chars long, prepending 'c'");
                    }

                    let tok = format!("Bearer {}", &s.slack_bot_token);

                    let fut = s
                        .validator
                        .validate_otp(&otp)
                        .and_then(move |decrypted_otp| {
                            debug!("Decrypted OTP: {:?}", decrypted_otp);
                            let mut rng = thread_rng();
                            let text;
                            let explanation;
                            match decrypted_otp {
                                Ok(_) => {
                                    text = rng.choose(&s.success).unwrap_or(&SUCCESS_TEXT);
                                    explanation = &s.success_explanation;
                                }
                                Err(OtpError::ReplayedOtp) => {
                                    text = rng.choose(&s.replayed).unwrap_or(&REPLAYED_TEXT);
                                    explanation = &s.replayed_explanation;
                                }
                                Err(e) => {
                                    return Err(actix_web::error::ErrorBadRequest(e));
                                }
                            }

                            let esc_text = slack_escape_text(&text.replace("$o", &otp))
                                .replace("$u", &format!("<@{}>", m.event.user));
                            let explanation = &explanation.replace("$o", &otp);

                            let json = serde_json::json!({
                                "channel": m.event.channel,
                                "thread_ts": m.event.thread_ts,
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
                                                "text": slack_escape_text(explanation)
                                            }
                                        ]
                                    }
                                ]
                            });
                            Ok(json)
                        })
                        .and_then(|reply| {
                            let client = Client::default();

                            client
                                .post(SLACK_POST_MESSAGE_ENDPOINT)
                                .header("Authorization", tok)
                                .send_json(&reply)
                                .map_err(error::Error::from)
                        })
                        .and_then(|_| Ok(HttpResponse::Ok().finish()))
                        .or_else(|_| Ok(HttpResponse::Ok().finish()));

                    Box::new(fut) as Box<dyn Future<Item = _, Error = _>>
                }
            },
        );

    Box::new(f)
}

fn main() -> Result<(), io::Error> {
    env_logger::Builder::new()
        .parse(&std::env::var("YUBOTP_LOG").unwrap_or_default())
        .init();

    let settings =
        match Settings::new(&std::env::var("YUBOTP_CFG").unwrap_or("config.toml".to_owned())) {
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
        settings.otpvalidation.apihosts,
    );

    let address = &settings.server.address;
    let port = settings.server.port;

    let vapp = Arc::new(ValidatorApp {
        validator: validator,
        slack_bot_token: settings.slack.bottoken,
        slack_signing_secret: settings.slack.signingsecret,
        success: settings.answers.success,
        replayed: settings.answers.replayed,
        success_explanation: settings.answers.success_explanation,
        replayed_explanation: settings.answers.replayed_explanation,
    });

    HttpServer::new(move || {
        App::new()
            .data(Arc::clone(&vapp))
            .wrap(middleware::Logger::default())
            .service(web::resource("/").route(web::post().to_async(handle_req)))
            .service(web::resource("/health").route(web::get().to(|| "OK")))
    })
    .bind(format!("{}:{}", address, port))?
    .run()
}
