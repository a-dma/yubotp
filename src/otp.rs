use actix_web::*;
use regex::{Regex, RegexBuilder};

use serde_derive::Serialize;

use lazy_static::lazy_static;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::iter;

use hmac::{Hmac, Mac, NewMac};
use sha1::Sha1;

use actix_web::client::Client;

lazy_static! {
    static ref CAPTURE_OTP_RE: Regex = RegexBuilder::new("([cbdefghijklnrtuvx.pys]{43,44})$")
        .case_insensitive(true)
        .build()
        .unwrap();
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
    api_host: String,
}

type HmacSha1 = Hmac<Sha1>;

impl OtpValidator {
    pub fn new(client_id: String, api_key: Vec<u8>, api_host: String) -> Self {
        OtpValidator {
            client_id,
            api_key,
            api_host,
        }
    }

    pub async fn validate_otp(
        &self,
        otp: &str,
    ) -> std::result::Result<std::result::Result<DecryptedOtp, OtpError>, Error> {
        let mut rng = thread_rng();
        let chars: String = iter::repeat(())
            .map(|()| -> char { rng.sample(Alphanumeric).into() })
            .take(40)
            .collect();

        self.validate_otp_internal(&self.api_host, &otp, &chars)
            .await
    }

    async fn validate_otp_internal(
        &self,
        api: &str,
        otp: &str,
        nonce: &str,
    ) -> std::result::Result<std::result::Result<DecryptedOtp, OtpError>, Error> {
        let client = Client::default();
        let query_string = format!(
            "{}?timestamp=1&id={}&nonce={}&otp={}",
            api, self.client_id, nonce, otp
        );

        let api_key = self.api_key.clone();
        let mut raw_resp = client.get(query_string).send().await?;
        let response = raw_resp.body().await?;

        let s = match String::from_utf8(response.to_vec()) {
            Ok(parsed) => parsed,
            Err(err) => return Err(actix_web::error::ErrorInternalServerError(err)),
        };
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
        let h = if let Ok(decoded) = base64::decode(h) {
            decoded
        } else {
            return Ok(Err(OtpError::BadSignature));
        };

        let mut hmac = HmacSha1::new_varkey(&api_key).expect("Key length not valid");
        hmac.update(message.as_bytes());
        if hmac.verify(&h).is_err() {
            return Ok(Err(OtpError::BadSignature));
        }

        let status = match CAPTURE_STATUS_RE
            .captures_iter(&s)
            .last()
            .and_then(|m| m.get(1))
        {
            Some(s) => s.as_str(),
            None => {
                return Err(actix_web::error::ErrorInternalServerError(
                    "Missing status in response",
                ))
            }
        };

        if status != "OK" {
            return match status {
                "BAD_OTP" => Ok(Err(OtpError::BadOtp)),
                "REPLAYED_OTP" => Ok(Err(OtpError::ReplayedOtp)),
                "BAD_SIGNATURE" => Ok(Err(OtpError::BadSignature)),
                "MISSING_PARAMETER" => Ok(Err(OtpError::MissingParameter)),
                "NO_SUCH_CLIENT" => Ok(Err(OtpError::NoSuchClient)),
                "OPERATION_NOT_ALLOWED" => Ok(Err(OtpError::OperationNotAllowed)),
                "BACKEND_ERROR" => Ok(Err(OtpError::BackendError)),
                "NOT_ENOUGH_ANSWERS" => Ok(Err(OtpError::NotEnoughAnswers)),
                "REPLAYED_REQUEST" => Ok(Err(OtpError::ReplayedRequest)),
                _ => Err(actix_web::error::ErrorInternalServerError("Unknown status")),
            };
        }

        let timestamp = match CAPTURE_TIMESTAMP_RE
            .captures_iter(&s)
            .last()
            .and_then(|m| m.get(1))
        {
            Some(s) => match s.as_str().parse() {
                Ok(t) => t,
                Err(e) => return Err(actix_web::error::ErrorInternalServerError(e)),
            },
            None => {
                return Err(actix_web::error::ErrorInternalServerError(
                    "Missing timestamp in response",
                ))
            }
        };

        let session_ctr = match CAPTURE_SESSION_CTR_RE
            .captures_iter(&s)
            .last()
            .and_then(|m| m.get(1))
        {
            Some(s) => match s.as_str().parse() {
                Ok(c) => c,
                Err(e) => return Err(actix_web::error::ErrorInternalServerError(e)),
            },
            None => {
                return Err(actix_web::error::ErrorInternalServerError(
                    "Missing sessioncounter in response",
                ))
            }
        };

        let session_use = match CAPTURE_SESSION_USE_RE
            .captures_iter(&s)
            .last()
            .and_then(|m| m.get(1))
        {
            Some(s) => match s.as_str().parse() {
                Ok(u) => u,
                Err(e) => return Err(actix_web::error::ErrorInternalServerError(e)),
            },
            None => {
                return Err(actix_web::error::ErrorInternalServerError(
                    "Missing sessionuse in response",
                ))
            }
        };

        Ok(Ok(DecryptedOtp {
            timestamp,
            session_ctr,
            session_use,
        }))
    }
}

pub fn extract_otp(message: &str) -> Option<String> {
    CAPTURE_OTP_RE
        .captures_iter(message)
        .last()
        .and_then(|m| m.get(0))
        .map(|o| o.as_str().to_lowercase())
}
