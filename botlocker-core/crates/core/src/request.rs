use std::net::IpAddr;

/// Platform-neutral view of an incoming request. Adapters fill this in;
/// the core never reads raw HTTP types.
#[derive(Debug, Clone)]
pub struct NormalizedRequest {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    /// Header names are lowercase. Order is the order the adapter saw them.
    pub headers: Vec<(String, String)>,
    pub client_ip: IpAddr,
    /// Requires a GeoIP/ASN database. `None` when the platform doesn't provide it.
    pub asn: Option<u32>,
    /// Requires a TLS-aware front. `None` when the platform doesn't expose it.
    pub tls_fingerprint: Option<String>,
}

impl NormalizedRequest {
    /// Case-insensitive header lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn user_agent(&self) -> &str {
        self.header("user-agent").unwrap_or("")
    }

    pub fn path_and_query(&self) -> String {
        match &self.query {
            Some(q) => format!("{}?{}", self.path, q),
            None => self.path.clone(),
        }
    }
}
