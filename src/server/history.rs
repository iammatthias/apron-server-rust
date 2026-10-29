//! history (§4.3): a room's records in a window, within the reply size and
//! the read limits.

use std::sync::Arc;

use rust_stdlib::encoding::json::jsontext::Value;

use super::client::{Client, Frame};
use super::config::{MAX_HISTORY_PAGE_SIZE, MAX_HISTORY_REPLY_BYTES};
use super::limits::{refused, Allowance, Category, Charge, Principal, Rate, Scope};
use super::protocol::*;
use super::rooms::{parse_bound, RoomState};
use super::server::{LogRecord, RecordKind, Server, State, DEFAULT_ROOM_ID};

/// A history reply's bytes besides its records: its id, `more`, the
/// partition keys, and the log_id bounds.
const HISTORY_ENVELOPE_BYTES: usize = 256;

fn parse_limit(params: &Params, default_limit: usize) -> Result<usize, RpcError> {
    let Some(raw) = params.get("limit") else {
        return Ok(default_limit);
    };
    let mut value: i64 = 0;
    if rust_stdlib::encoding::json::v2::unmarshal(&raw.0, &mut value, &[]).is_err() || value <= 0 {
        return Err(invalid_params("limit must be a positive integer"));
    }
    Ok((value as usize).min(MAX_HISTORY_PAGE_SIZE))
}

/// Returns the records of a log, which is in log_id order, within the
/// inclusive bounds.
fn window(log: &[i64], after: Option<i64>, before: Option<i64>) -> &[i64] {
    let mut log = log;
    if let Some(after) = after {
        let start = log.partition_point(|id| *id < after);
        log = &log[start..];
    }
    if let Some(before) = before {
        let end = log.partition_point(|id| *id <= before);
        log = &log[..end];
    }
    log
}

impl State {
    /// Charges a history page to the user's and the IP's minute and day, and
    /// the server's day, or to none.
    fn charge_history_locked(&mut self, c: &Client, user_id: &str) -> Result<(), RpcError> {
        let limits = &self.config.limits;
        let (user, ip) = (
            Principal::User(user_id.to_owned()),
            Principal::Ip(c.ip_key.clone()),
        );
        let charges = [
            Charge {
                scope: Scope::History,
                principal: &user,
                allowance: Allowance::rate(limits.user_history, limits.user_history_day),
            },
            Charge {
                scope: Scope::History,
                principal: &ip,
                allowance: Allowance::rate(limits.ip_history, limits.ip_history_day),
            },
            Charge {
                scope: Scope::History,
                principal: &Principal::Server,
                allowance: Allowance::rate(Rate::per_minute(0), limits.server_history_day),
            },
        ];
        self.limits.charge(&charges, 1).map_err(|refusal| {
            let message = match (refusal.row, refusal.daily) {
                (_, false) => "History request limit reached",
                (0, true) => "Daily history limit reached",
                (1, true) => "Daily history limit reached for this network",
                (_, true) => "Daily history limit reached for the server",
            };
            refused(message, refusal.retry_after(), Some(Category::Read))
        })
    }
}

impl State {
    /// Returns a window of the log (§4.3): with room_id, that room's log,
    /// which needs no membership, only a room the user can see; without it,
    /// the log of every room the user joined, as one log. limit counts
    /// records of every kind; the slice is partitioned into rooms, messages,
    /// reactions, and membership, each omitted when empty.
    pub fn history_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        let room_id = parse_string(&req.params, "room_id", false)?;
        let has_room = req.params.contains_key("room_id");
        let after = parse_bound(&req.params, "after")?;
        let before = parse_bound(&req.params, "before")?;
        let limit = parse_limit(&req.params, self.config.history_page_size)?;

        let user_id = self.user_of(c)?;
        let rooms: Vec<&RoomState> = if has_room {
            let Some(r) = self.visible_room_locked(&user_id, &room_id) else {
                return Err(invalid_params(format!("Unknown room {}", quote(&room_id))));
            };
            vec![r]
        } else {
            self.users[&user_id]
                .joined
                .iter()
                .filter(|id| self.room_visible_to(id, &user_id))
                .filter_map(|id| self.rooms.get(id))
                .collect()
        };
        // The rooms' windows merge by log_id from the end the page starts
        // at, until limit+1 records: a move snapshot in two of them is one
        // record, the same in both logs, and comes once.
        let has_after = after.is_some();
        let mut windows: Vec<&[i64]> = Vec::new();
        let mut latest = 0i64;
        for r in &rooms {
            latest = latest.max(r.latest_id);
            let records = window(&r.log, after, before);
            if !records.is_empty() {
                windows.push(records);
            }
        }
        let mut matching: Vec<i64> = Vec::new();
        while matching.len() <= limit {
            let mut next: Option<i64> = None;
            for records in &windows {
                if records.is_empty() {
                    continue;
                }
                let head = if has_after {
                    records[0]
                } else {
                    records[records.len() - 1]
                };
                next = Some(match next {
                    None => head,
                    Some(n) if (has_after && head < n) || (!has_after && head > n) => head,
                    Some(n) => n,
                });
            }
            let Some(next) = next else { break };
            matching.push(next);
            for records in windows.iter_mut() {
                if records.is_empty() {
                    continue;
                }
                if has_after && records[0] == next {
                    *records = &records[1..];
                } else if !has_after && records[records.len() - 1] == next {
                    *records = &records[..records.len() - 1];
                }
            }
        }
        if !has_after {
            matching.reverse();
        }
        // With room_id, the room's log starts at its creation. Without it,
        // the log of the joined rooms starts where the server's does, at the
        // default room's creation (§4.3.3); for a user in no rooms it is
        // empty, ending just before. Retention moves either start up to the
        // history floor, and a log retention emptied has none.
        let mut created = self
            .rooms
            .get(DEFAULT_ROOM_ID)
            .map(|r| r.created_id)
            .unwrap_or(0);
        if has_room {
            created = rooms[0].created_id;
        }
        let start = created.max(self.history_floor);
        if rooms.is_empty() {
            latest = start - 1;
        }
        let mut more = matching.len() > limit;
        if more {
            if has_after {
                matching.truncate(limit);
            } else {
                matching.remove(0);
            }
        }
        // A page also stops at MAX_HISTORY_REPLY_BYTES with its envelope,
        // keeping at least one record, so one request cannot hold the lock
        // to render an unbounded reply.
        let mut size = HISTORY_ENVELOPE_BYTES + req.id.len();
        for i in 0..matching.len() {
            let k = if has_after { i } else { matching.len() - 1 - i };
            size += self
                .records
                .get(&matching[k])
                .map_or(0, |r| r.raw.len() + 1);
            if size > MAX_HISTORY_REPLY_BYTES && i > 0 {
                if has_after {
                    matching.truncate(k);
                } else {
                    matching.drain(..=k);
                }
                more = true;
                break;
            }
        }
        let records: Vec<&LogRecord> = matching
            .iter()
            .filter_map(|id| self.records.get(id))
            .collect();
        let has_history = !rooms.is_empty() && start <= latest;
        let result = render_history(latest, start, has_history, &records, more, size);
        // Only a request that serves a page is counted.
        self.charge_history_locked(c, &user_id)?;
        // The records are already JSON: the reply is assembled from them
        // without decoding or re-encoding.
        c.enqueue_frame(Frame::from(raw_response(&req.id, &result)));
        Ok((Json::Raw(Value::from(result)), true))
    }
}

/// Assembles a history result (§4.3) from a window of records, with the
/// queried log's head and the start of its history, which is null for a log
/// of no rooms or one retention emptied.
pub fn render_history(
    latest: i64,
    created: i64,
    has_history: bool,
    matching: &[&LogRecord],
    more: bool,
    size: usize,
) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(size + matching.len() + 256);
    buf.extend_from_slice(b"{\"more\":");
    buf.extend_from_slice(if more { b"true" } else { b"false" });
    for (key, kind) in [
        ("rooms", RecordKind::Room),
        ("messages", RecordKind::Message),
        ("reactions", RecordKind::Reactions),
        ("memberships", RecordKind::Membership),
    ] {
        let mut first = true;
        for record in matching {
            if record.kind != kind {
                continue;
            }
            if first {
                buf.extend_from_slice(b",\"");
                buf.extend_from_slice(key.as_bytes());
                buf.extend_from_slice(b"\":[");
                first = false;
            } else {
                buf.push(b',');
            }
            buf.extend_from_slice(&record.raw);
        }
        if !first {
            buf.push(b']');
        }
    }
    let field = |buf: &mut Vec<u8>, key: &str, id: i64| {
        buf.extend_from_slice(b",\"");
        buf.extend_from_slice(key.as_bytes());
        buf.extend_from_slice(b"\":\"");
        buf.extend_from_slice(id.to_string().as_bytes());
        buf.push(b'"');
    };
    field(&mut buf, "latest_log_id", latest);
    if has_history {
        field(&mut buf, "history_log_id", created);
    } else {
        buf.extend_from_slice(b",\"history_log_id\":null");
    }
    if let (Some(first), Some(last)) = (matching.first(), matching.last()) {
        field(&mut buf, "first_log_id", first.id);
        field(&mut buf, "last_log_id", last.id);
    }
    buf.push(b'}');
    buf
}

impl Server {
    pub(crate) fn history(
        self: &Arc<Self>,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        self.lock().history_locked(c, req)
    }
}
