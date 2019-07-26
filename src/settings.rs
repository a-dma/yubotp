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
    pub apihosts: Vec<String>,
    pub apikey: String,
    pub clientid: String,
}

impl fmt::Display for OtpValidation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "OtpValidation (apiHosts: {:?}, apikey: ******, clientid: {})",
            self.apihosts, self.clientid
        )
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Answer {
    pub success: Vec<String>,
    pub replayed: Vec<String>,
    pub explanation: String
}

impl fmt::Display for Answer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Answer (success: {:?}, replayed: {:?}, explanation: {:?})",
            self.success, self.replayed, self.explanation
        )
    }
}


#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: Server,
    pub slack: Slack,
    pub otpvalidation: OtpValidation,
    pub answers: Answer,
}

impl fmt::Display for Settings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Settings ({}, {}, {}, {})",
            self.server, self.slack, self.otpvalidation, self.answers
        )
    }
}

impl Settings {
    pub fn new(file: &str) -> Result<Self, ConfigError> {
        let mut s = Config::default();

        s.set_default("server.address", "0.0.0.0")?;
        s.set_default("server.port", 8088)?;

        s.set_default(
            "otpvalidation.apihosts",
            vec![
                "https://api.yubico.com/wsapi/2.0/verify",
                "https://api2.yubico.com/wsapi/2.0/verify",
                "https://api3.yubico.com/wsapi/2.0/verify",
                "https://api4.yubico.com/wsapi/2.0/verify",
                "https://api5.yubico.com/wsapi/2.0/verify",
            ],
        )?;

        s.set_default("answers.success", vec!["Success"])?;
        s.set_default("answers.replayed", vec!["Replayed"])?;
        s.set_default("answers.explanation", "_The OTP has been consumed._")?;

        s.merge(File::with_name(&file))?;

        s.merge(Environment::with_prefix("yubotp").separator("_"))?;

        s.try_into()
    }
}
