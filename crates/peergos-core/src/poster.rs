//! HTTP transport, ported from `HttpPoster` / `JavaPoster`.
//!
//! Peergos quirk: `get` becomes a POST with an empty body when NOT talking to a
//! public server (browsers block cross-origin POST to localhost, which is the
//! security property relied on). Against a public Peergos server it is a real GET.

use crate::error::{Error, Result};
use async_trait::async_trait;

/// The default per-request timeout used by the Java client (15s).
pub const DEFAULT_TIMEOUT_MS: i32 = 15_000;

#[async_trait]
pub trait HttpPoster: Send + Sync {
    /// POST `payload` to `url`. `unzip` is advisory; gzip responses are always
    /// transparently decompressed by the transport.
    async fn post(&self, url: &str, payload: Vec<u8>, unzip: bool, timeout_ms: i32) -> Result<Vec<u8>>;

    async fn post_unzip(&self, url: &str, payload: Vec<u8>, timeout_ms: i32) -> Result<Vec<u8>> {
        self.post(url, payload, true, timeout_ms).await
    }

    async fn put(&self, url: &str, body: Vec<u8>, headers: Vec<(String, String)>) -> Result<Vec<u8>>;

    /// GET semantics: a real GET against a public server, else a POST with an
    /// empty body (see module docs).
    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        self.post_unzip(url, Vec::new(), DEFAULT_TIMEOUT_MS).await
    }
}

/// A reqwest-backed [`HttpPoster`].
pub struct ReqwestPoster {
    client: reqwest::Client,
    base: reqwest::Url,
    /// True when talking to a public server: `get` uses a real GET.
    use_get: bool,
    user_agent: Option<String>,
}

impl ReqwestPoster {
    pub fn new(base_url: &str, is_public_server: bool) -> Result<ReqwestPoster> {
        let mut base = base_url.to_string();
        if !base.ends_with('/') {
            base.push('/');
        }
        let base = reqwest::Url::parse(&base).map_err(|e| Error::Http(e.to_string()))?;
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| Error::Http(e.to_string()))?;
        Ok(ReqwestPoster {
            client,
            base,
            use_get: is_public_server,
            user_agent: None,
        })
    }

    pub fn with_user_agent(mut self, agent: impl Into<String>) -> Self {
        self.user_agent = Some(agent.into());
        self
    }

    fn url(&self, path: &str) -> Result<reqwest::Url> {
        self.base.join(path).map_err(|e| Error::Http(e.to_string()))
    }

    /// Map an HTTP response to bytes, applying the Java status-code policy.
    async fn finish(&self, resp: reqwest::Response) -> Result<Vec<u8>> {
        let status = resp.status().as_u16();
        // Peergos puts the server-side error message in the URL-encoded `Trailer`
        // response header (`HttpUtil.replyError`), not the body.
        let trailer = resp
            .headers()
            .get("Trailer")
            .and_then(|v| v.to_str().ok())
            .map(url_decode);
        let body = resp.bytes().await.map_err(|e| Error::Http(e.to_string()))?;
        match status {
            200 => Ok(body.to_vec()),
            429 | 502 | 503 | 504 => Err(Error::RateLimited),
            other => {
                let msg = trailer.unwrap_or_else(|| String::from_utf8_lossy(&body).to_string());
                if msg.contains("Storage quota reached") || msg.contains("Storage+quota+reached") {
                    Err(Error::QuotaExceeded(msg))
                } else if msg.contains("Queue full") {
                    Err(Error::RateLimited)
                } else {
                    Err(Error::Http(format!("status {other}: {msg}")))
                }
            }
        }
    }
}

/// Decode an `application/x-www-form-urlencoded` string (`URLDecoder.decode`):
/// `+` → space, `%XX` → byte.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = |c: u8| (c as char).to_digit(16);
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

#[async_trait]
impl HttpPoster for ReqwestPoster {
    async fn post(&self, url: &str, payload: Vec<u8>, _unzip: bool, _timeout_ms: i32) -> Result<Vec<u8>> {
        let mut req = self.client.post(self.url(url)?);
        if let Some(agent) = &self.user_agent {
            req = req.header("User-Agent", agent);
        }
        // Empty payload => no body (matches BodyPublishers.noBody()).
        if !payload.is_empty() {
            req = req.body(payload);
        }
        let resp = req.send().await.map_err(|e| Error::Http(e.to_string()))?;
        self.finish(resp).await
    }

    async fn put(&self, url: &str, body: Vec<u8>, headers: Vec<(String, String)>) -> Result<Vec<u8>> {
        let mut req = self.client.put(self.url(url)?).body(body);
        if let Some(agent) = &self.user_agent {
            req = req.header("User-Agent", agent);
        }
        for (k, v) in headers {
            if k != "Host" && k != "Content-Length" {
                req = req.header(k, v);
            }
        }
        let resp = req.send().await.map_err(|e| Error::Http(e.to_string()))?;
        self.finish(resp).await
    }

    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        if self.use_get {
            let mut req = self.client.get(self.url(url)?);
            if let Some(agent) = &self.user_agent {
                req = req.header("User-Agent", agent);
            }
            let resp = req.send().await.map_err(|e| Error::Http(e.to_string()))?;
            self.finish(resp).await
        } else {
            self.post_unzip(url, Vec::new(), DEFAULT_TIMEOUT_MS).await
        }
    }
}
