//! The user_ids a guest's passkey registration mints, after
//! apron-server-cloudflare's `userIdSlug` and `candidateUserIdFor`
//! (test/auth.integration.test.ts).

use std::cell::Cell;

use rust_stdlib::regexp::Regexp;

use crate::server::users::{candidate_user_id, user_id_slug, USER_ID_SLUG_ATTEMPTS};

#[test]
fn test_user_id_slugs_follow_cloudflare() {
    let cases = [
        ("Foo", "foo"),
        ("  Foo Bar!! ", "foo_bar"),
        // Cloudflare decomposes first and gets "zoe_angstrom"; without NFKD
        // each accented letter is a run of other characters.
        ("Zoë Ångström", "zo_ngstr_m"),
        ("A very long display name indeed", "a_very_long_disp"),
        ("abcdefghijklmno pq", "abcdefghijklmno"),
        ("Alexandria Ocasio-Cortez the 3rd", "alexandria_ocasi"),
        ("日本語", ""),
        ("", ""),
        ("!!!", ""),
        ("Guest", ""),
        ("guest 12", ""),
        ("Bot", ""),
        ("bot-army", ""),
        ("Guesthouse", "guesthouse"),
        ("Bottle", "bottle"),
        // user_<n> is this server's email-account counter.
        ("User", ""),
        ("user 7", ""),
        ("Username", "username"),
    ];
    for (name, want) in cases {
        assert_eq!(user_id_slug(name), want, "slug of {name:?}");
    }
}

#[test]
fn test_candidate_user_id_takes_the_first_free_slug() {
    let calls = Cell::new(0);
    let id = candidate_user_id("Foo", |_| {
        calls.set(calls.get() + 1);
        false
    });
    assert_eq!(calls.get(), 1);
    assert!(
        Regexp::new(r"^foo_[0-9]{4}$").unwrap().match_string(&id),
        "{id}"
    );
}

#[test]
fn test_candidate_user_id_falls_back_after_eight_taken() {
    let tried = std::cell::RefCell::new(Vec::new());
    let id = candidate_user_id("Foo", |id| {
        tried.borrow_mut().push(id.to_owned());
        true
    });
    assert_eq!(USER_ID_SLUG_ATTEMPTS, 8);
    assert_eq!(tried.borrow().len(), 8);
    let slugged = Regexp::new(r"^foo_[0-9]{4}$").unwrap();
    assert!(tried.borrow().iter().all(|id| slugged.match_string(id)));
    assert!(
        Regexp::new(r"^u_[A-Za-z0-9_-]{22}$")
            .unwrap()
            .match_string(&id),
        "{id}"
    );
}

#[test]
fn test_candidate_user_id_without_a_slug_is_random() {
    let calls = Cell::new(0);
    for name in ["", "Guest 3", "日本語"] {
        let id = candidate_user_id(name, |_| {
            calls.set(calls.get() + 1);
            false
        });
        assert!(
            Regexp::new(r"^u_[A-Za-z0-9_-]{22}$")
                .unwrap()
                .match_string(&id),
            "{id}"
        );
    }
    assert_eq!(calls.get(), 0);
}
