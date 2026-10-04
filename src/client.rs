//! Typed client for the PBS REST API (`/api2/json`, port 8007).
//!
//! Requests go through a [`Transport`] so every call site is testable against
//! recorded fixtures; production uses [`ReqwestTransport`]. The API token
//! secret never appears in `Debug` output or in an error: every error string is
//! passed through [`ApiToken::redact`] before it leaves this module.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde::de::DeserializeOwned;
use plugin_toolkit::serde_json::{self, Value};

use crate::tls::{self, TlsPolicy};

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

#[derive(Clone)]
pub struct HttpCall {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl fmt::Debug for HttpCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, v)| {
                if k.eq_ignore_ascii_case("authorization") {
                    (k.as_str(), "<redacted>")
                } else {
                    (k.as_str(), v.as_str())
                }
            })
            .collect();
        f.debug_struct("HttpCall")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &headers)
            .field("body_len", &self.body.as_ref().map(Vec::len))
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct HttpReply {
    pub status: u16,
    pub body: Vec<u8>,
}

pub trait Transport: Send + Sync {
    fn send(&self, call: HttpCall) -> BoxFut<'_, Result<HttpReply>>;
}

/// The real HTTPS transport, honouring the endpoint's [`TlsPolicy`].
pub struct ReqwestTransport {
    http: plugin_toolkit::reqwest::Client,
}

impl ReqwestTransport {
    pub fn new(policy: &TlsPolicy) -> Result<Self> {
        let http = match policy {
            TlsPolicy::Verify => ApiClientBuilder::new().timeout(TIMEOUT).build()?,
            TlsPolicy::Insecure => ApiClientBuilder::new()
                .timeout(TIMEOUT)
                .insecure(true)
                .build()?,
            TlsPolicy::Pinned(fp) => plugin_toolkit::reqwest::Client::builder()
                .tls_backend_preconfigured(tls::pinned_client_config(*fp)?)
                .connect_timeout(TIMEOUT)
                .timeout(TIMEOUT)
                .build()
                .context("build pinned PBS client")?,
        };
        Ok(Self { http })
    }
}

impl Transport for ReqwestTransport {
    fn send(&self, call: HttpCall) -> BoxFut<'_, Result<HttpReply>> {
        Box::pin(async move {
            let method =
                plugin_toolkit::reqwest::Method::from_bytes(call.method.as_str().as_bytes())
                    .context("http method")?;
            let mut req = self.http.request(method, &call.url);
            for (k, v) in &call.headers {
                req = req.header(k.as_str(), v.as_str());
            }
            if let Some(body) = call.body {
                req = req.body(body);
            }
            let resp = req.send().await?;
            let status = resp.status().as_u16();
            let body = resp.bytes().await?.to_vec();
            Ok(HttpReply { status, body })
        })
    }
}

/// A PBS API token: `<user>@<realm>!<tokenid>` plus its secret.
#[derive(Clone)]
pub struct ApiToken {
    id: String,
    secret: String,
}

impl ApiToken {
    pub fn new(id: impl Into<String>, secret: impl Into<String>) -> Result<Self> {
        let id = id.into();
        let secret = secret.into();
        validate_token_id(&id)?;
        if secret.trim().is_empty() {
            bail!("PBS token secret for '{id}' is empty");
        }
        Ok(Self { id, secret })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    fn header(&self) -> String {
        format!("PBSAPIToken={}:{}", self.id, self.secret)
    }

    /// Replace every occurrence of the secret in `text`.
    pub fn redact(&self, text: &str) -> String {
        redact_secret(text, &self.secret)
    }
}

impl fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiToken")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

pub fn redact_secret(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_string();
    }
    text.replace(secret, "<redacted>")
}

/// `<user>@<realm>!<tokenid>`: the shape PBS expects before the `:` in the
/// `PBSAPIToken` header.
pub fn validate_token_id(id: &str) -> Result<()> {
    let (user, token) = id
        .split_once('!')
        .ok_or_else(|| anyhow!("PBS token id '{id}' must look like user@realm!tokenid"))?;
    let ok = user
        .split_once('@')
        .is_some_and(|(u, r)| !u.is_empty() && !r.is_empty())
        && !token.is_empty()
        && !id.contains([':', ' ', '\n']);
    if !ok {
        bail!("PBS token id '{id}' must look like user@realm!tokenid");
    }
    Ok(())
}

pub struct PbsClient {
    base: String,
    token: ApiToken,
    transport: Box<dyn Transport>,
}

impl fmt::Debug for PbsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PbsClient")
            .field("base", &self.base)
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}

/// Successful response envelope. Some endpoints (task log) put siblings such as
/// `total` next to `data`, so the whole object is kept.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub data: Value,
    pub extra: serde_json::Map<String, Value>,
}

impl PbsClient {
    /// `base` is the server origin (`https://host:8007`); `/api2/json` is added
    /// here.
    pub fn new(base: &str, token: ApiToken, transport: Box<dyn Transport>) -> Self {
        let trimmed = base.trim_end_matches('/');
        let base = trimmed
            .strip_suffix("/api2/json")
            .unwrap_or(trimmed)
            .to_string();
        Self {
            base,
            token,
            transport,
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn token_id(&self) -> &str {
        self.token.id()
    }

    pub async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T> {
        self.decode(self.call(Method::Get, path, query, None).await?)
    }

    pub async fn get_envelope(&self, path: &str, query: &[(&str, String)]) -> Result<Envelope> {
        self.call(Method::Get, path, query, None).await
    }

    pub async fn post<T: DeserializeOwned>(&self, path: &str, body: Value) -> Result<T> {
        self.decode(self.call(Method::Post, path, &[], Some(body)).await?)
    }

    pub async fn put<T: DeserializeOwned>(&self, path: &str, body: Value) -> Result<T> {
        self.decode(self.call(Method::Put, path, &[], Some(body)).await?)
    }

    pub async fn delete<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T> {
        self.decode(self.call(Method::Delete, path, query, None).await?)
    }

    fn decode<T: DeserializeOwned>(&self, env: Envelope) -> Result<T> {
        serde_json::from_value(env.data).map_err(|e| {
            anyhow!(
                "{}",
                self.token.redact(&format!("decode PBS response: {e}"))
            )
        })
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<Envelope> {
        let mut url = format!("{}/api2/json{}", self.base, path);
        if !query.is_empty() {
            url.push('?');
            url.push_str(&encode_query(query));
        }
        let mut headers = vec![
            ("authorization".to_string(), self.token.header()),
            ("accept".to_string(), "application/json".to_string()),
        ];
        let body = match body {
            Some(v) => {
                headers.push(("content-type".to_string(), "application/json".to_string()));
                Some(serde_json::to_vec(&v)?)
            }
            None => None,
        };
        let what = format!("{} {}", method.as_str(), path);
        let reply = self
            .transport
            .send(HttpCall {
                method,
                url,
                headers,
                body,
            })
            .await
            .map_err(|e| anyhow!("{}", self.token.redact(&format!("PBS {what}: {e:#}"))))?;
        parse_reply(&what, reply).map_err(|e| anyhow!("{}", self.token.redact(&format!("{e:#}"))))
    }
}

fn parse_reply(what: &str, reply: HttpReply) -> Result<Envelope> {
    let parsed: Option<Value> = serde_json::from_slice(&reply.body).ok();
    if !(200..300).contains(&reply.status) {
        bail!(
            "PBS {what}: HTTP {}: {}",
            reply.status,
            error_message(parsed.as_ref(), &reply.body)
        );
    }
    let Some(Value::Object(mut obj)) = parsed else {
        bail!("PBS {what}: response is not a JSON object");
    };
    let data = obj.remove("data").unwrap_or(Value::Null);
    Ok(Envelope { data, extra: obj })
}

/// PBS reports failures as `{"message": …}` or, for parameter errors,
/// `{"errors": {"param": "why"}}`.
fn error_message(parsed: Option<&Value>, raw: &[u8]) -> String {
    if let Some(v) = parsed {
        let mut parts = Vec::new();
        if let Some(m) = v.get("message").and_then(Value::as_str) {
            parts.push(m.trim().to_string());
        }
        if let Some(errs) = v.get("errors").and_then(Value::as_object) {
            for (k, e) in errs {
                parts.push(format!(
                    "{k}: {}",
                    e.as_str().unwrap_or(&e.to_string()).trim()
                ));
            }
        }
        if !parts.is_empty() {
            return parts.join("; ");
        }
    }
    let text = String::from_utf8_lossy(raw);
    text.chars()
        .take(300)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Percent-encode one path segment or query component (RFC 3986 unreserved
/// characters pass through).
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn encode_query(query: &[(&str, String)]) -> String {
    query
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
pub(crate) mod mock {
    //! Recorded-fixture transport: every request is matched by method + path
    //! (query ignored unless the route includes one) and logged for assertions.

    use std::sync::{Arc, Mutex};

    use super::*;

    /// `(method, path, status, body)`.
    type Fixture = (Method, String, u16, String);

    #[derive(Clone, Default)]
    pub struct MockTransport {
        routes: Arc<Mutex<Vec<Fixture>>>,
        pub calls: Arc<Mutex<Vec<HttpCall>>>,
    }

    impl MockTransport {
        pub fn new() -> Self {
            Self::default()
        }

        /// Register a reply. Later registrations for the same route win, so a
        /// test can change what PBS returns between steps.
        pub fn on(&self, method: Method, path: &str, status: u16, body: &str) -> &Self {
            self.routes
                .lock()
                .unwrap()
                .push((method, path.to_string(), status, body.to_string()));
            self
        }

        pub fn ok(&self, method: Method, path: &str, data: Value) -> &Self {
            self.on(method, path, 200, &json!({ "data": data }).to_string())
        }

        pub fn client(&self) -> PbsClient {
            PbsClient::new(
                "https://pbs.test:8007",
                ApiToken::new("root@pam!orca", "s3cr3t-token-value").unwrap(),
                Box::new(self.clone()),
            )
        }

        /// `METHOD /path` of every call made, in order.
        pub fn log(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .map(|c| format!("{} {}", c.method.as_str(), strip_base(&c.url)))
                .collect()
        }

        pub fn mutations(&self) -> Vec<String> {
            self.log()
                .into_iter()
                .filter(|l| !l.starts_with("GET "))
                .collect()
        }

        pub fn body_of(&self, n: usize) -> Value {
            let calls = self.calls.lock().unwrap();
            serde_json::from_slice(calls[n].body.as_deref().unwrap_or(b"null")).unwrap()
        }
    }

    fn strip_base(url: &str) -> &str {
        url.split_once("/api2/json").map_or(url, |(_, p)| p)
    }

    impl Transport for MockTransport {
        fn send(&self, call: HttpCall) -> BoxFut<'_, Result<HttpReply>> {
            Box::pin(async move {
                let full = strip_base(&call.url).to_string();
                let path_only = full.split('?').next().unwrap_or_default().to_string();
                self.calls.lock().unwrap().push(call.clone());
                let routes = self.routes.lock().unwrap();
                let hit = routes
                    .iter()
                    .rev()
                    .find(|(m, p, _, _)| *m == call.method && (*p == full || *p == path_only));
                match hit {
                    Some((_, _, status, body)) => Ok(HttpReply {
                        status: *status,
                        body: body.as_bytes().to_vec(),
                    }),
                    None => Ok(HttpReply {
                        status: 404,
                        body: format!(
                            "{{\"data\":null,\"message\":\"no fixture for {} {full}\"}}",
                            call.method.as_str()
                        )
                        .into_bytes(),
                    }),
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockTransport;
    use super::*;

    #[tokio::test]
    async fn unwraps_the_data_envelope_and_keeps_siblings() {
        let m = MockTransport::new();
        m.on(
            Method::Get,
            "/x",
            200,
            r#"{"data":[{"n":1,"t":"hi"}],"total":1}"#,
        );
        let env = m.client().get_envelope("/x", &[]).await.unwrap();
        assert_eq!(env.data[0]["t"], "hi");
        assert_eq!(env.extra["total"], 1);
    }

    #[tokio::test]
    async fn sends_the_pbs_token_header_and_json_body() {
        let m = MockTransport::new();
        m.ok(Method::Post, "/y", Value::Null);
        let _: Value = m.client().post("/y", json!({"a": 1})).await.unwrap();
        let call = m.calls.lock().unwrap()[0].clone();
        let auth = &call
            .headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .unwrap()
            .1;
        assert_eq!(auth, "PBSAPIToken=root@pam!orca:s3cr3t-token-value");
        assert_eq!(m.body_of(0), json!({"a": 1}));
        assert!(call.url.starts_with("https://pbs.test:8007/api2/json/y"));
    }

    #[tokio::test]
    async fn error_carries_pbs_message_and_never_the_secret() {
        let m = MockTransport::new();
        m.on(
            Method::Get,
            "/z",
            403,
            r#"{"data":null,"message":"permission check failed for s3cr3t-token-value"}"#,
        );
        let err = m
            .client()
            .get::<Value>("/z", &[])
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("HTTP 403"), "{err}");
        assert!(err.contains("permission check failed"), "{err}");
        assert!(!err.contains("s3cr3t-token-value"), "secret leaked: {err}");
    }

    #[tokio::test]
    async fn parameter_errors_are_flattened() {
        let m = MockTransport::new();
        m.on(
            Method::Post,
            "/p",
            400,
            r#"{"data":null,"errors":{"name":"value does not match the regex pattern"}}"#,
        );
        let err = m
            .client()
            .post::<Value>("/p", json!({}))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("name: value does not match"), "{err}");
    }

    #[test]
    fn debug_output_redacts_secret() {
        let t = ApiToken::new("a@pbs!b", "very-secret").unwrap();
        assert!(!format!("{t:?}").contains("very-secret"));
        let call = HttpCall {
            method: Method::Get,
            url: "https://x".into(),
            headers: vec![("Authorization".into(), t.header())],
            body: None,
        };
        assert!(!format!("{call:?}").contains("very-secret"));
    }

    #[test]
    fn token_id_shape_is_checked() {
        assert!(validate_token_id("root@pam!orca").is_ok());
        assert!(validate_token_id("root@pam").is_err());
        assert!(validate_token_id("root!x").is_err());
        assert!(validate_token_id("root@pam!x:y").is_err());
        assert!(ApiToken::new("root@pam!x", " ").is_err());
    }

    #[test]
    fn encodes_upids_and_namespaces() {
        assert_eq!(encode("hosts/freyr"), "hosts%2Ffreyr");
        assert_eq!(
            encode("UPID:pbs:00000001:root@pam!orca:"),
            "UPID%3Apbs%3A00000001%3Aroot%40pam%21orca%3A"
        );
        assert_eq!(
            encode_query(&[("ns", "a b".into()), ("x", "1".into())]),
            "ns=a%20b&x=1"
        );
    }

    #[test]
    fn base_accepts_api_root_or_origin() {
        let m = MockTransport::new();
        let c = PbsClient::new(
            "https://h:8007/api2/json/",
            ApiToken::new("a@b!c", "d").unwrap(),
            Box::new(m),
        );
        assert_eq!(c.base(), "https://h:8007");
    }

    /// The real transport against a one-shot local HTTP server: proves the
    /// header and body survive reqwest, independent of the mock.
    #[tokio::test]
    async fn reqwest_transport_round_trips_against_a_local_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let mut seen = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                seen.extend_from_slice(&buf[..n]);
                if n == 0 || seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let body = include_str!("../tests/fixtures/datastore_list.json");
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&seen).to_string()
        });
        let client = PbsClient::new(
            &format!("http://{addr}"),
            ApiToken::new("root@pam!orca", "tok").unwrap(),
            Box::new(ReqwestTransport::new(&TlsPolicy::Verify).unwrap()),
        );
        let stores: Vec<Value> = client.get("/admin/datastore", &[]).await.unwrap();
        assert_eq!(stores.len(), 2);
        let request = server.await.unwrap().to_lowercase();
        assert!(
            request.starts_with("get /api2/json/admin/datastore "),
            "{request}"
        );
        assert!(request.contains("authorization: pbsapitoken=root@pam!orca:tok"));
    }
}
