use actix_web::*;
use regex::Regex;

use serde_derive::Serialize;

use lazy_static::lazy_static;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::iter;

use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha1::Sha1;

use futures::future::Future;

use actix_web::client::Client;

lazy_static! {
    static ref CAPTURE_OTP_RE: Regex = Regex::new("([cbdefghijklnrtuv]{44})$").unwrap(); // This can also be {32,64}
}

lazy_static! {
    static ref CAPTURE_TIMESTAMP_RE: Regex = Regex::new("timestamp=([0-9]*)").unwrap();
}

lazy_static! {
    static ref CAPTURE_SESSION_CTR_RE: Regex = Regex::new("sessioncounter=([0-9]*)").unwrap();
}

lazy_static! {
    static ref CAPTURE_SESSION_USE_RE: Regex = Regex::new("sessionuse=([0-9]*)").unwrap();
}

lazy_static! {
    static ref CAPTURE_STATUS_RE: Regex = Regex::new("status=([A-Z_]*)").unwrap();
}

#[derive(Debug, Serialize)]
pub struct DecryptedOtp {
    pub timestamp: u32,
    pub session_ctr: u32,
    pub session_use: u32,
}

#[derive(Debug)]
pub enum OtpError {
    BadOtp,
    ReplayedOtp,
    BadSignature,
    MissingParameter,
    NoSuchClient,
    OperationNotAllowed,
    BackendError,
    NotEnoughAnswers,
    ReplayedRequest,
}

impl std::fmt::Display for OtpError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            OtpError::BadOtp => write!(f, "The OTP has invalid format"),
            OtpError::ReplayedOtp => write!(f, "The OTP has already been seen by the service"),
            OtpError::BadSignature => write!(f, "The HMAC signature verification failed"),
            OtpError::MissingParameter => write!(f, "The request lacks a parameter"),
            OtpError::NoSuchClient => write!(f, "The request ID does not exist"),
            OtpError::OperationNotAllowed => {
                write!(f, "The request ID is not allowed to verify OTPs")
            }
            OtpError::BackendError => write!(f, "Unexpected error"),
            OtpError::NotEnoughAnswers => {
                write!(f, "The server could not get the requested number of syncs")
            }
            OtpError::ReplayedRequest => {
                write!(f, "The server has seen the OTP+Nonce combination before")
            }
        }
    }
}

impl std::error::Error for OtpError {}

#[derive(Debug, Clone)]
pub struct OtpValidator {
    client_id: String,
    api_key: Vec<u8>,
    api_hosts: Vec<String>,
}

impl OtpValidator {
    pub fn new(client_id: String, api_key: Vec<u8>, api_hosts: Vec<String>) -> Self {
        OtpValidator {
            client_id,
            api_key,
            api_hosts,
        }
    }

    pub fn validate_otp(
        &self,
        otp: &str,
    ) -> impl Future<Item = std::result::Result<DecryptedOtp, OtpError>, Error = Error> {
        let mut rng = thread_rng();
        let chars: String = iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .take(40)
            .collect();

        let v = self
            .api_hosts
            .iter()
            .map(|x| self.validate_otp_internal(x, &otp, &chars))
            .collect::<Vec<_>>();

        futures::future::join_all(v).map(|mut results| {
            for i in 0..results.len() {
                if results[i].is_ok() {
                    return results.remove(i);
                }
            }

            results.remove(0)
        })
    }

    fn validate_otp_internal(
        &self,
        api: &str,
        otp: &str,
        nonce: &str,
    ) -> impl Future<Item = std::result::Result<DecryptedOtp, OtpError>, Error = Error> {
        let client = Client::default();
        let query_string = format!(
            "{}?timestamp=1&id={}&nonce={}&otp={}",
            api, self.client_id, nonce, otp
        );

        let api_key = self.api_key.clone();
        client
            .get(query_string)
            .send()
            .map_err(Error::from)
            .and_then(|mut res| res.body().from_err())
            .and_then(move |response| {
                let s = String::from_utf8(response.to_vec()).unwrap();
                let mut h = String::new();
                let mut sorted_result = s
                    .trim()
                    .lines()
                    .filter(|s| {
                        if s.starts_with("h=") {
                            h = s[2..].to_string();
                            false
                        } else {
                            true
                        }
                    })
                    .collect::<Vec<_>>();
                sorted_result.sort();
                let message = sorted_result.join("&");

                let mut hmac = Hmac::new(Sha1::new(), &api_key);
                hmac.input(message.as_bytes());
                let digest = hmac.result();
                if h != base64::encode(digest.code()) {
                    return futures::finished(Err(OtpError::BadSignature));
                }

                let status = match CAPTURE_STATUS_RE
                    .captures_iter(&s)
                    .last()
                    .and_then(|m| m.get(1))
                {
                    Some(s) => s.as_str(),
                    None => unreachable!("Missing status in response"),
                };

                if status != "OK" {
                    return match status {
                        "BAD_OTP" => futures::finished(Err(OtpError::BadOtp)),
                        "REPLAYED_OTP" => futures::finished(Err(OtpError::ReplayedOtp)),
                        "BAD_SIGNATURE" => futures::finished(Err(OtpError::BadSignature)),
                        "MISSING_PARAMETER" => futures::finished(Err(OtpError::MissingParameter)),
                        "NO_SUCH_CLIENT" => futures::finished(Err(OtpError::NoSuchClient)),
                        "OPERATION_NOT_ALLOWED" => {
                            futures::finished(Err(OtpError::OperationNotAllowed))
                        }
                        "BACKEND_ERROR" => futures::finished(Err(OtpError::BackendError)),
                        "NOT_ENOUGH_ANSWERS" => futures::finished(Err(OtpError::NotEnoughAnswers)),
                        "REPLAYED_REQUEST" => futures::finished(Err(OtpError::ReplayedRequest)),
                        _ => unreachable!("Unknown status"),
                    };
                }

                let timestamp = match CAPTURE_TIMESTAMP_RE
                    .captures_iter(&s)
                    .last()
                    .and_then(|m| m.get(1))
                {
                    Some(s) => s.as_str().parse().expect("Unable to parse timestamp"),
                    None => unreachable!("Missing status in response"),
                };

                let session_ctr = match CAPTURE_SESSION_CTR_RE
                    .captures_iter(&s)
                    .last()
                    .and_then(|m| m.get(1))
                {
                    Some(s) => s.as_str().parse().expect("Unable to parse sessioncounter"),
                    None => unreachable!("Missing status in response"),
                };

                let session_use = match CAPTURE_SESSION_USE_RE
                    .captures_iter(&s)
                    .last()
                    .and_then(|m| m.get(1))
                {
                    Some(s) => s.as_str().parse().expect("Unable to parse sessionuse"),
                    None => unreachable!("Missing status in response"),
                };

                futures::finished(Ok(DecryptedOtp {
                    timestamp,
                    session_ctr,
                    session_use,
                }))
            })
    }
}

pub fn extract_otp(message: &str) -> Option<String> {
    CAPTURE_OTP_RE
        .captures_iter(message)
        .last()
        .and_then(|m| m.get(0))
        .and_then(|o| Some(o.as_str().to_owned()))
}
