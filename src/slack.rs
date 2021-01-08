use serde::de::Error;
use serde_derive::{Deserialize, Serialize};

use log::debug;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Event {
    Chal(Challenge),
    Msg(Box<OuterEvent>),
}

#[derive(Debug, Deserialize)]
pub struct Challenge {
    pub token: String,
    pub challenge: String,
    #[serde(rename = "type")]
    pub event_type: String,
}

#[derive(Debug, Deserialize)]
pub struct SimpleMessage {
    #[serde(rename = "type")]
    pub event_type: String,
    pub channel: String,
    pub user: String,
    pub text: String,
    pub ts: String,
    pub thread_ts: Option<String>,
    pub event_ts: String,
    pub channel_type: String,
    pub client_msg_id: String,
}

#[derive(Debug, Deserialize)]
pub struct BotMessage {
    #[serde(rename = "type")]
    pub event_type: String,
    pub channel: String,
    pub username: String,
    pub bot_id: String,
    pub text: String,
    pub ts: String,
    pub thread_ts: Option<String>,
    pub event_ts: String,
    pub channel_type: String,
}

#[derive(Debug)]
pub enum Message {
    Simple(SimpleMessage),
    Bot(BotMessage),
}

#[derive(Debug, Deserialize)]
pub struct OuterEvent {
    pub token: String,
    pub team_id: String,
    pub api_app_id: String,
    pub event: Message,
    #[serde(rename = "type")]
    pub event_type: String,
    pub authed_users: Vec<String>,
    pub event_id: String,
    pub event_time: u64,
}

impl<'de> serde::Deserialize<'de> for Message {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let content: serde_json::Value = serde_json::Value::deserialize(deserializer)?;
        if let Some(ref subtype) = content.get("subtype") {
            match subtype {
                &serde_json::Value::String(st) if st == "bot_message" => {
                    serde_json::from_value::<BotMessage>(content)
                        .map(Message::Bot)
                        .map_err(|e| D::Error::custom(&format!("{}", e)))
                }
                _ => panic!("unknown message subtype {}", subtype),
            }
        } else {
            serde_json::from_value::<SimpleMessage>(content)
                .map(Message::Simple)
                .map_err(|e| D::Error::custom(&format!("{}", e)))
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Response {
    Chal(ChallengeResponse),
}
