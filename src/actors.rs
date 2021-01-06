use std::collections::HashSet;

use actix::prelude::{Actor, Context, Handler, Message};
use actix::AsyncContext;
use log::debug;

const DELAY: u64 = 5;

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
            // Schedule the cached otp to be deleted in `DELAY` seconds. If for some
            // reason the main request fails and a `RemoveOtp` message is not sent,
            // the otp would be cached forever otherwise.
            ctx.run_later(std::time::Duration::from_secs(DELAY), move |actor, _ctx| {
                if actor.otp_cache.remove(&otp) {
                    debug!("Removed OTP {} from cache after {}s delay", otp, DELAY);
                }
            });
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
