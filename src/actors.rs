use std::collections::{HashMap, HashSet};

use actix::prelude::{Actor, Context, Handler, Message};
use actix::AsyncContext;
use log::debug;

use lazy_static::lazy_static;

use rand::prelude::SliceRandom;
use rand::thread_rng;

use crate::slack::PostMessageResponse;

const OTP_CACHE_REMOVE_DELAY: u64 = 5;
const BOT_MESSAGE_REMOVE_DELAY: u64 = 3 * 60 * 60; // 3 hours

lazy_static! {
    static ref SUCCESS_TEXT: String = String::from("OTP validated");
}

lazy_static! {
    static ref REPLAYED_TEXT: String = String::from("Replayed OTP");
}

lazy_static! {
    static ref DELETED_TEXT: String = String::from("The OTP is gone");
}

pub struct DuplicateMessagesActor {
    otp_cache: HashSet<String>,
}

impl DuplicateMessagesActor {
    pub fn new() -> Self {
        DuplicateMessagesActor {
            otp_cache: HashSet::new(),
        }
    }
}

impl Actor for DuplicateMessagesActor {
    type Context = Context<Self>;
}

#[derive(Message, Debug)]
#[rtype(result = "bool")]
pub struct CacheOrIgnoreOtp(pub String);

#[derive(Message, Debug)]
#[rtype(result = "bool")]
pub struct RemoveOtp(pub String);

impl Handler<CacheOrIgnoreOtp> for DuplicateMessagesActor {
    type Result = bool;

    fn handle(&mut self, msg: CacheOrIgnoreOtp, ctx: &mut Self::Context) -> Self::Result {
        let otp = msg.0;
        let stored = self.otp_cache.insert(otp.clone());

        if stored {
            // Schedule the cached otp to be deleted after a delay. If for some
            // reason the main request fails and a `RemoveOtp` message is not sent,
            // the otp would be cached forever otherwise.
            ctx.run_later(
                std::time::Duration::from_secs(OTP_CACHE_REMOVE_DELAY),
                move |actor, _ctx| {
                    if actor.otp_cache.remove(&otp) {
                        debug!(
                            "Removed OTP {} from cache after {}s delay",
                            otp, OTP_CACHE_REMOVE_DELAY
                        );
                    }
                },
            );
        }

        stored
    }
}

impl Handler<RemoveOtp> for DuplicateMessagesActor {
    type Result = bool;

    fn handle(&mut self, msg: RemoveOtp, _ctx: &mut Self::Context) -> Self::Result {
        debug!("Removing OTP {} from cache", msg.0);
        self.otp_cache.remove(&msg.0)
    }
}

pub struct BotResponsesActor {
    sent_messages: HashMap<String, PostMessageResponse>,
}

impl BotResponsesActor {
    pub fn new() -> Self {
        BotResponsesActor {
            sent_messages: HashMap::new(),
        }
    }
}

impl Actor for BotResponsesActor {
    type Context = Context<Self>;
}

#[derive(Message, Debug)]
#[rtype(result = "bool")]
pub struct NewBotMessage {
    original_message_ts: String,
    bot_message_info: PostMessageResponse,
}

impl NewBotMessage {
    pub fn new(original_message_ts: String, bot_message_info: PostMessageResponse) -> Self {
        NewBotMessage {
            original_message_ts,
            bot_message_info,
        }
    }
}

impl Handler<NewBotMessage> for BotResponsesActor {
    type Result = bool;

    fn handle(&mut self, msg: NewBotMessage, ctx: &mut Self::Context) -> Self::Result {
        debug!(
            "Adding bot message response info {:?} to message {:?}",
            msg.bot_message_info, msg.original_message_ts
        );
        let original_message_ts = msg.original_message_ts;
        let res = self
            .sent_messages
            .insert(original_message_ts.clone(), msg.bot_message_info)
            .is_none();

        // Schedule the bot response info to be deleted after a delay.
        ctx.run_later(
            std::time::Duration::from_secs(BOT_MESSAGE_REMOVE_DELAY),
            move |actor, _ctx| {
                if actor.sent_messages.remove(&original_message_ts).is_some() {
                    debug!(
                        "Removed sent message info {} from cache after {}s delay",
                        original_message_ts, BOT_MESSAGE_REMOVE_DELAY
                    );
                }
            },
        );

        res
    }
}

#[derive(Message, Debug)]
#[rtype(result = "Option<PostMessageResponse>")]
pub struct RetrieveBotMessageInfo(pub String);

impl Handler<RetrieveBotMessageInfo> for BotResponsesActor {
    type Result = Option<PostMessageResponse>;

    fn handle(&mut self, msg: RetrieveBotMessageInfo, _ctx: &mut Self::Context) -> Self::Result {
        debug!("Retrieving PostMessageResponse for event ts {}", msg.0);
        self.sent_messages.remove(&msg.0)
    }
}

#[derive(Debug)]
pub enum Reply {
    Success,
    Replayed,
    Deleted,
}

pub struct RepliesSelectionActor {
    success_orig: Vec<String>,
    success: Vec<String>,
    replayed_orig: Vec<String>,
    replayed: Vec<String>,
    deleted_orig: Vec<String>,
    deleted: Vec<String>,
}

impl RepliesSelectionActor {
    pub fn new(success: Vec<String>, replayed: Vec<String>, deleted: Vec<String>) -> Self {
        RepliesSelectionActor {
            success_orig: success.clone(),
            success,
            replayed_orig: replayed.clone(),
            replayed,
            deleted_orig: deleted.clone(),
            deleted,
        }
    }

    fn shuffle(&mut self, msg_type: Reply) {
        let mut rng = thread_rng();

        match msg_type {
            Reply::Success => {
                self.success = self.success_orig.clone();
                self.success.shuffle(&mut rng);
            }
            Reply::Replayed => {
                self.replayed = self.replayed_orig.clone();
                self.replayed.shuffle(&mut rng);
            }
            Reply::Deleted => {
                self.deleted = self.deleted_orig.clone();
                self.deleted.shuffle(&mut rng);
            }
        }
    }

    fn pick_reply(&mut self, msg_type: Reply) -> String {
        let replies: &mut Vec<String>;
        let default_reply: &str;

        match msg_type {
            Reply::Success => {
                replies = &mut self.success;
                default_reply = &SUCCESS_TEXT;
            }
            Reply::Replayed => {
                replies = &mut self.replayed;
                default_reply = &REPLAYED_TEXT;
            }
            Reply::Deleted => {
                replies = &mut self.deleted;
                default_reply = &DELETED_TEXT;
            }
        }

        let reply = replies.pop().unwrap_or_else(|| default_reply.to_string());

        if replies.is_empty() {
            self.shuffle(msg_type)
        }

        reply
    }
}

impl Actor for RepliesSelectionActor {
    type Context = Context<Self>;
}

#[derive(Message, Debug)]
#[rtype(result = "String")]
pub struct NewReply {
    pub reply_type: Reply,
}

impl Handler<NewReply> for RepliesSelectionActor {
    type Result = String;

    fn handle(&mut self, msg: NewReply, _ctx: &mut Self::Context) -> Self::Result {
        self.pick_reply(msg.reply_type)
    }
}
