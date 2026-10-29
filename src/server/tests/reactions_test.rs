//! Reaction entries (§4.7): stored fully qualified, compared without
//! U+FE0F, and custom emoji keys, ported from apron-server-cloudflare's
//! test/mutations.test.ts.

use std::sync::Arc;

use super::helpers::*;
use super::persist_test::start_with_store;
use crate::obj;
use crate::server::persist::ENTRY_MESSAGE;
use crate::server::protocol::*;
use crate::store::{self, Store};

fn emojis_of(broadcast: &Object) -> Json {
    broadcast["reactions"].as_list()[0].as_object().unwrap()["emojis"].clone()
}

#[test]
fn test_reaction_entries_are_qualified_and_keys_known() {
    let server = new_test_server(super::helpers::default_config());
    let mut c = dial_test_client(&server);
    let (id, _) = save(
        &mut c,
        "target",
        obj! {"body" => obj! {"text" => "react to me"}},
    );
    // ❤ is text-default: stored as ❤️, once, whichever form came first.
    let set = react(
        &mut c,
        "h1",
        &id,
        &["\u{2764}", "\u{2764}\u{FE0F}", "🏳\u{200D}🌈", "👍🏽"],
    );
    assert_eq!(emojis_of(&set), strings(&["\u{2764}\u{FE0F}", "🏳️‍🌈", "👍🏽"]));
    // The same set in other forms is no change.
    let same = c.result(
        "reactions",
        "h2",
        obj! {"message_id" => id.as_str(), "emojis" => strings(&["👍🏽", "🏳️‍🌈", "\u{2764}"])},
    );
    assert!(same.is_empty());
    c.expect_quiet();
    // A key must be a custom emoji the server has; this one has none.
    c.expect_error(
        "reactions",
        "key",
        obj! {"message_id" => id.as_str(), "emojis" => strings(&[":partyparrot:"])},
        CODE_INVALID_PARAMS,
    );
    // Text that is not a key, such as a lone colon word, is kept as written.
    let colon = react(&mut c, "colon", &id, &[":party"]);
    assert_eq!(emojis_of(&colon), strings(&[":party"]));
}

/// Sets stored before entries were qualified load qualified, and the store
/// is rewritten with them.
#[test]
fn test_stored_reaction_sets_are_migrated() {
    let dir = TempDir::new("apron-reactions-");
    let kept: Arc<dyn Store> = Arc::new(store::Memory::new());
    let mut server = start_with_store(kept.clone(), &format!("{dir}/a"));
    let mut c = dial_test_client(&server);
    let (id, _) = save(&mut c, "target", obj! {"body" => obj! {"text" => "old"}});
    react(&mut c, "set", &id, &["👍"]);
    {
        let mut st = server.app.lock();
        let set = st
            .messages
            .get_mut(&id)
            .unwrap()
            .reactions
            .values_mut()
            .next()
            .unwrap();
        set.emojis = vec!["\u{2764}".into(), "\u{2764}\u{FE0F}".into(), "👍".into()];
        st.touch_message(&id);
    }
    drop(c);
    server.stop();

    let mut server = start_with_store(kept.clone(), &format!("{dir}/a"));
    let set = server.app.lock().messages[&id]
        .reactions
        .values()
        .next()
        .unwrap()
        .emojis
        .clone();
    assert_eq!(set, ["\u{2764}\u{FE0F}", "👍"]);
    server.stop();
    let mut stored = String::new();
    kept.load(&mut |e| {
        if e.kind == ENTRY_MESSAGE && e.id == id {
            stored = String::from_utf8(e.value.unwrap_or_default()).unwrap();
        }
        Ok(())
    })
    .unwrap();
    assert!(
        stored.contains("\"emojis\":[\"\u{2764}\u{FE0F}\",\"👍\"]"),
        "{stored}"
    );
}
