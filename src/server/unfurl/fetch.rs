//! Fetching pages and their og:images.

use std::io::Read;
use std::sync::Arc;

use rust_stdlib::mime;
use rust_stdlib::net::http::client::{CheckRedirect, Client};
use rust_stdlib::net::http::header::BoxError;
use rust_stdlib::net::http::Body;
use rust_stdlib::net::http::Request as HttpRequest;
use rust_stdlib::net::url;
use rust_stdlib::time::Duration;

use super::page::{parse_page, Meta};
use crate::obj;
use crate::server::embeds::image_config;
use crate::server::outbound::{self, DialCheck};
use crate::server::protocol::*;

pub const MAX_REDIRECTS: usize = 3;
/// Bounds each request, the body included.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// The part of a page read for its metadata.
pub const MAX_PAGE_BYTES: u64 = 512 << 10;
pub const MAX_IMAGE_BYTES: u64 = 2 << 20;

pub const USER_AGENT: &str = concat!(
    "Mozilla/5.0 (compatible; aprond/",
    env!("CARGO_PKG_VERSION"),
    "; link preview; +https://github.com/iammatthias/apron-server-rust)"
);

/// An og:image the server hosts: a PNG, JPEG, GIF, or WebP whose header
/// reads as its decoded format.
#[derive(Debug, PartialEq, Eq)]
pub struct Image {
    pub bytes: Vec<u8>,
    pub content_type: String,
    pub width: i64,
    pub height: i64,
}

/// A page's metadata, and its og:image when the server can host it.
#[derive(Debug, PartialEq, Eq)]
pub struct Preview {
    pub meta: Meta,
    pub image: Option<Image>,
}

impl Preview {
    /// The og of the preview, its image at `image_url`.
    pub fn og(&self, image_url: Option<&str>) -> Object {
        let mut og = Object::new();
        for (key, value) in [
            ("title", &self.meta.title),
            ("description", &self.meta.description),
            ("site_name", &self.meta.site_name),
        ] {
            if !value.is_empty() {
                og.insert(key.into(), value.as_str().into());
            }
        }
        if let (Some(image), Some(url)) = (&self.image, image_url) {
            let mut media = obj! {
                "url" => url,
                "type" => image.content_type.as_str(),
                "width" => image.width,
                "height" => image.height,
            };
            if !self.meta.image_alt.is_empty() {
                media.insert("alt".into(), self.meta.image_alt.as_str().into());
            }
            og.insert("image".into(), media.into());
        }
        og
    }
}

/// A 200 answer: the URL answered after redirects, its Content-Type, and at
/// most the limit of its body, `over` when the body went past it.
struct Fetched {
    url: url::Url,
    content_type: String,
    bytes: Vec<u8>,
    over: bool,
}

/// Closes a response body however the read of it ends.
struct Closing<'a>(&'a Body);

impl Drop for Closing<'_> {
    fn drop(&mut self) {
        let _ = self.0.close();
    }
}

/// GETs pages and images with the limits of link previews: http(s) only, at
/// most MAX_REDIRECTS redirects, a timeout over the whole exchange, and
/// every dialed address, after each redirect too, passed by the dial check.
pub struct Fetcher {
    client: Client,
}

impl Fetcher {
    pub fn new(check: DialCheck, timeout: Duration) -> Fetcher {
        // The transport refuses schemes other than http and https.
        let check_redirect: CheckRedirect = Arc::new(|_: &HttpRequest, via: &[HttpRequest]| {
            if via.len() > MAX_REDIRECTS {
                return Err(format!("stopped after {MAX_REDIRECTS} redirects").into());
            }
            Ok(())
        });
        Fetcher {
            client: outbound::client(check, timeout, check_redirect, |_| {}),
        }
    }

    /// GETs url and reads at most `limit` bytes of a 200 answer.
    fn get(&self, target: &str, accept: &str, limit: u64) -> Result<Fetched, BoxError> {
        let mut request = HttpRequest::new("GET", target)?;
        request.header.set("User-Agent", USER_AGENT);
        request.header.set("Accept", accept);
        let response = self.client.do_request(request)?;
        let Some(body) = &response.body else {
            return Err("no body".into());
        };
        let _closing = Closing(body);
        if response.status_code != 200 {
            return Err(format!("status {}", response.status_code).into());
        }
        let mut bytes = Vec::new();
        body.clone().take(limit + 1).read_to_end(&mut bytes)?;
        let over = bytes.len() as u64 > limit;
        bytes.truncate(limit as usize);
        Ok(Fetched {
            url: response
                .request
                .as_ref()
                .map(|r| r.url.clone())
                .unwrap_or_default(),
            content_type: response.header.get("Content-Type").unwrap_or("").to_owned(),
            bytes,
            over,
        })
    }

    /// Fetches a page and its og:image. `None` when the page cannot be read,
    /// is not HTML, or gives no title, description, or usable image.
    pub fn preview(&self, target: &str) -> Option<Preview> {
        let page = self
            .get(target, "text/html,application/xhtml+xml", MAX_PAGE_BYTES)
            .ok()?;
        let (media_type, _) = mime::parse_media_type(&page.content_type);
        if media_type != "text/html" && media_type != "application/xhtml+xml" {
            return None;
        }
        let meta = parse_page(&String::from_utf8_lossy(&page.bytes), &page.url);
        let image = if meta.image.is_empty() {
            None
        } else {
            self.image(&meta.image)
        };
        if meta.title.is_empty() && meta.description.is_empty() && image.is_none() {
            return None;
        }
        Some(Preview { meta, image })
    }

    /// Downloads an og:image of at most MAX_IMAGE_BYTES, declared as an image
    /// and with the header of a PNG, JPEG, GIF, or WebP. The format the
    /// header reads as is its type: sites often declare `image/jpg`, or one
    /// type for another a CDN negotiated.
    fn image(&self, target: &str) -> Option<Image> {
        let fetched = self.get(target, "image/*", MAX_IMAGE_BYTES).ok()?;
        if fetched.over
            || !mime::parse_media_type(&fetched.content_type)
                .0
                .starts_with("image/")
        {
            return None;
        }
        let (config, format) = image_config(&fetched.bytes[..])?;
        Some(Image {
            bytes: fetched.bytes,
            content_type: format!("image/{format}"),
            width: i64::from(config.width),
            height: i64::from(config.height),
        })
    }
}
