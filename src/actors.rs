use std::collections::HashSet;

use actix::prelude::{Actor, Context, Handler, Message};
use log::debug;

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

    fn handle(&mut self, msg: CacheOrIgnoreOtp, _ctx: &mut Self::Context) -> Self::Result {
        self.otp_cache.insert(msg.0)
    }
}

impl Handler<RemoveOtp> for DuplicateMessagesActor {
    type Result = bool;

    fn handle(&mut self, msg: RemoveOtp, _ctx: &mut Self::Context) -> Self::Result {
        debug!("Removing OTP {} from cache", msg.0);
        self.otp_cache.remove(&msg.0)
    }
}
