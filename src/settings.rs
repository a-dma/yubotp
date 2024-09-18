use config::{Config, ConfigError, Environment, File};

use serde_derive::Deserialize;

use std::fmt;

#[derive(Debug, Deserialize, Clone)]
pub struct Server {
    pub address: String,
    pub port: u32,
}

impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Server (address: {}, port: {})", self.address, self.port)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Slack {
    pub bottoken: String,
    pub signingsecret: String,
}

impl fmt::Display for Slack {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Slack (bottoken: ******, signingsecret: ******)")
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct OtpValidation {
    pub apihost: String,
    pub apikey: String,
    pub clientid: String,
}

impl fmt::Display for OtpValidation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "OtpValidation (apiHost: {:?}, apikey: ******, clientid: {})",
            self.apihost, self.clientid
        )
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Answer {
    pub newdevice: Vec<String>,
    pub success: Vec<String>,
    pub replayed: Vec<String>,
    pub deleted: Vec<String>,
}

impl fmt::Display for Answer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Answer (success: {:?}, replayed: {:?}, deleted: {:?})",
            self.success, self.replayed, self.deleted
        )
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Explanation {
    pub success: String,
    pub replayed: String,
}

impl fmt::Display for Explanation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Explanation (success: {:?}, replayed: {:?})",
            self.success, self.replayed
        )
    }
}

#[derive(Debug, Deserialize, Clone, Copy)]
pub struct CounterThresholds {
    pub ctr: u32,
    pub usage: u32,
}

impl fmt::Display for CounterThresholds {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Counter thresholds (session counter: {}, usage counter {}",
            self.ctr, self.usage
        )
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: Server,
    pub slack: Slack,
    pub otpvalidation: OtpValidation,
    pub answers: Answer,
    pub explanation: Explanation,
    pub counterthresholds: CounterThresholds,
}

impl fmt::Display for Settings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Settings ({}, {}, {}, {}, {}, {})",
            self.server,
            self.slack,
            self.otpvalidation,
            self.answers,
            self.explanation,
            self.counterthresholds,
        )
    }
}

impl Settings {
    pub fn new(file: &str) -> Result<Self, ConfigError> {
        let builder = Config::builder()
            .set_default("server.address", "0.0.0.0")?
            .set_default::<&str, u64>("server.port", 8088)?
            .set_default(
                "otpvalidation.apihost",
                "https://api.yubico.com/wsapi/2.0/verify",
            )?
            .set_default("answers.newdevice", vec!["Success new device"])?
            .set_default("answers.success", vec!["Success"])?
            .set_default("answers.replayed", vec!["Replayed"])?
            .set_default("answers.deleted", vec!["Deleted"])?
            .set_default("explanation.success", "_The OTP has been consumed._")?
            .set_default(
                "explanation.replayed",
                "_Replayed OTP, it has already been consumed._",
            )?
            .set_default("counterthresholds.ctr", 0)?
            .set_default("counterthresholds.usage", 0)?
            .add_source(File::with_name(file).required(false))
            .add_source(Environment::with_prefix("yubotp").separator("_"));

        let c = builder.build()?;

        c.try_deserialize()
    }
}
