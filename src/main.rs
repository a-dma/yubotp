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

use rand::{thread_rng, Rng};

use hex;

use std::sync::Arc;

mod otp;

use otp::{OtpError, OtpValidator};

mod settings;

use settings::Settings;

static EXIT_FAILURE: i32 = 1;

static SLACK_POST_MESSAGE_ENDPOINT: &str = "https://slack.com/api/chat.postMessage";

struct ValidatorApp {
    validator: otp::OtpValidator,
    slack_bot_token: String,
    slack_signing_secret: String,
    success: Vec<String>,
    replayed: Vec<String>,
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
    Simple(String),
}

#[derive(Debug, Serialize)]
struct Reply {
    channel: String,
    text: String,
    thread_ts: Option<String>,
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
                return into_box_dyn(Err(ErrorBadRequest("Bad request".to_string())));
            }
        };
        let req_signature = match headers.get("X-Slack-Signature") {
            Some(header) => header,
            None => {
                debug!("Unable to extract signature header");
                return into_box_dyn(Err(ErrorBadRequest("Bad request".to_string())));
            }
        };

        let req_signature = match req_signature.to_str() {
            Ok(s) => s,
            Err(_) => {
                debug!("Unable to convert signature header to string");
                return into_box_dyn(Err(ErrorBadRequest("Bad request".to_string())));
            }
        };

        if !req_signature.starts_with("v0=") {
            debug!("Malformed Slack signature");
            return into_box_dyn(Err(ErrorBadRequest("Bad request".to_string())));
        }

        let req_signature = hex::decode(&req_signature[3..]).unwrap();
        let mut hmac = Hmac::new(Sha256::new(), signing_secret.as_bytes());
        hmac.input(b"v0:");
        hmac.input(req_timestamp.as_bytes());
        hmac.input(b":");
        hmac.input(&bytes);

        let res = hmac.result();
        if res.code() != &*req_signature {
            debug!("Wrong Slack signature");
            return into_box_dyn(Err(ErrorBadRequest("Bad request".to_string())));
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
                    let otp = match otp::extract_otp(&m.event.text) {
                        Some(otp) => otp,
                        None => {
                            return into_box_dyn(Ok(HttpResponse::Ok().json(ok_resp())));
                        }
                    };

                    debug!("Found otp: {:?}", otp);

                    let tok = format!("Bearer {}", &s.slack_bot_token);

                    let fut = s
                        .validator
                        .validate_otp(&otp)
                        .and_then(move |decrypted_otp| {
                            debug!("Decrypted OTP: {:?}", decrypted_otp);
                            let mut rng = thread_rng();
                            let text = rng
                                .choose(match decrypted_otp {
                                    Ok(_) => &s.success,
                                    Err(OtpError::ReplayedOtp) => &s.replayed,
                                    Err(e) => {
                                        return Err(actix_web::error::ErrorBadRequest(e));
                                    }
                                })
                                .unwrap()
                                .replace("$u", &format!("<@{}>", m.event.user));
                            Ok(Reply {
                                channel: m.event.channel,
                                text,
                                thread_ts: m.event.thread_ts,
                            })
                        })
                        .and_then(|reply| {
                            let client = Client::default();

                            client
                                .post(SLACK_POST_MESSAGE_ENDPOINT)
                                .header("Authorization", tok)
                                .send_json(&reply)
                                .map_err(error::Error::from)
                        })
                        .and_then(|_| Ok(HttpResponse::Ok().json(ok_resp())));

                    Box::new(fut) as Box<dyn Future<Item = _, Error = _>>
                }
            },
        );

    Box::new(f)
}

fn main() {
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
    });

    HttpServer::new(move || {
        App::new()
            .data(Arc::clone(&vapp))
            .service(web::resource("/").route(web::post().to_async(handle_req)))
            .service(web::resource("/health").route(web::get().to(|| "OK")))
    })
    .bind(format!("{}:{}", address, port))
    .unwrap()
    .run()
    .unwrap();
}

fn ok_resp() -> Response {
    Response::Simple("OK".to_string())
}
