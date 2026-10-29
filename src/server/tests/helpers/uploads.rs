//! Upload bodies and the embeds that name them.

use crate::server::protocol::*;

use super::*;

/// A 3x2 PNG.
pub fn test_png() -> Vec<u8> {
    use rust_stdlib::image;
    let mut buf = Vec::new();
    image::png::encode(&mut buf, &image::Rgba::new(image::rect(0, 0, 3, 2))).expect("encode png");
    buf
}

pub fn embeds_of(snapshot: &Object) -> Vec<Object> {
    snapshot
        .get("body")
        .and_then(Json::as_object)
        .and_then(|body| body.get("embeds"))
        .map(Json::as_list)
        .unwrap_or(&[])
        .iter()
        .map(|value| value.as_object().cloned().unwrap())
        .collect()
}

/// Posts a message with new upload or stream embeds and returns its result,
/// which must follow the sender's copy of the pending snapshot (§1); the
/// snapshot is added to the result as "snapshot".
pub fn post_embeds(c: &mut TestClient, id: &str, params: Object) -> Object {
    let (before, mut result) = c.request("message", id, params);
    assert!(
        before.len() == 1
            && !result
                .get("embeds")
                .map(Json::as_list)
                .unwrap_or(&[])
                .is_empty(),
        "message with embeds: {before:?} then {result:?}"
    );
    result.insert(
        "snapshot".into(),
        notification_params(&before[0], "message").into(),
    );
    result
}

/// A body of `size` bytes, at least 16, that starts with a PNG signature,
/// so uploads that only need some image take it.
pub fn png_of_size(size: usize) -> Vec<u8> {
    let mut body = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    body.resize(size.max(body.len()), 0);
    body
}
