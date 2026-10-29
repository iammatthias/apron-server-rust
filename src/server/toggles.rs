//! `/toggle`, an extension Go lacks (docs/DEVIATIONS.md), following
//! apron-server-cloudflare's (its SPEC.md, section 5, Admins): an admin
//! turns typing activity, uploads, user status or adding others to rooms
//! off or on for everyone, kept across restarts.

use std::sync::Arc;

use super::commands::private_notice;
use super::protocol::*;
use super::server::{Client, State};

/// A feature `/toggle` turns off and on. Each is on by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Feature {
    /// Typing and read cursors through `activity` (§4.7).
    Activity,
    /// Upload embeds and `/avatar` (§4.8).
    Uploads,
    /// The statuses others are shown (§4.5).
    Presence,
    /// Accounts adding others to rooms with `room_join` and a `user_id`.
    AddMember,
}

impl Feature {
    pub const ALL: [Feature; 4] = [
        Feature::Activity,
        Feature::Uploads,
        Feature::Presence,
        Feature::AddMember,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Feature::Activity => "activity",
            Feature::Uploads => "uploads",
            Feature::Presence => "presence",
            Feature::AddMember => "addmember",
        }
    }

    pub fn named(name: &str) -> Option<Feature> {
        Feature::ALL.into_iter().find(|f| f.name() == name)
    }

    /// The notice `/toggle` answers with, for the feature now `on` or off.
    fn notice(self, on: bool) -> &'static str {
        match (self, on) {
            (Feature::Presence, true) => "Status is now **on**: others see who is online, idle, busy (`dnd`) or offline.",
            (Feature::Presence, false) => "Status is now **off**: no one's status is shown, and connected clients were told to clear the ones they were shown.",
            (Feature::Activity, true) => "Activity is now **on**: typing is relayed, and new connections are offered it.",
            (Feature::Activity, false) => "Activity is now **off**: typing is no longer relayed, and new connections are not offered it.",
            (Feature::AddMember, true) => "Adding members is now **on**: any registered user can add another to a room.",
            (Feature::AddMember, false) => "Adding members is now **off**: only admins can add others to a room, and owners their bots.",
            (Feature::Uploads, true) => "Uploads are now **on**.",
            (Feature::Uploads, false) => "Uploads are now **off**: new attachments and avatars are refused, and new connections are not offered uploads.",
        }
    }
}

/// Refuses a new upload embed or `/avatar` while uploads are off.
pub const UPLOADS_OFF: &str = "Uploads are turned off here";

impl State {
    pub fn feature_on(&self, feature: Feature) -> bool {
        !self.features_off.contains(&feature)
    }

    /// `/toggle <feature>` turns the feature off or on for everyone and
    /// tells the sender which with a ~private notice before the result (§1).
    /// New connections are offered what is on; connected ones keep what
    /// they were offered. Presence turned off tells every connection that
    /// each user's status is now `""`, and turned on, what it is again.
    pub(super) fn toggle_command(
        &mut self,
        c: &Arc<Client>,
        room_id: &str,
        _body: &Object,
        args: &str,
    ) -> Result<Object, RpcError> {
        let Some(feature) = Feature::named(args) else {
            let names: Vec<&str> = Feature::ALL.iter().map(|f| f.name()).collect();
            return Err(invalid_params(format!(
                "Usage: /toggle {}",
                names.join("|")
            )));
        };
        let on = !self.feature_on(feature);
        if on {
            self.features_off.remove(&feature);
        } else {
            self.features_off.insert(feature);
        }
        if feature == Feature::Presence {
            self.republish_statuses_locked();
        }
        c.enqueue(&private_notice(&self.rooms[room_id], feature.notice(on)));
        Ok(Object::new())
    }

    /// Publishes every user's shown status at once, past the coalescing,
    /// after presence changed, and sends each change to those who share a
    /// room with the user.
    fn republish_statuses_locked(&mut self) {
        let ids: Vec<String> = self.users.keys().cloned().collect();
        for id in ids {
            if self.publish_locked(&id) {
                let sharers = self.sharers_locked(&id);
                self.send_status_locked(&id, &sharers);
            }
        }
    }
}
