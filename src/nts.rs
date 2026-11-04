//! Network Time Security (RFC 8915): NTS-KE over TLS 1.3 and authenticated NTPv4.

use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aes_siv::{KeyInit, siv::Aes128Siv};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};

use crate::ProtocolError;
use crate::ntp::{self, NtpResponse, NtpTimestamp};

pub const NTS_KE_PORT: u16 = 4460;
pub const NTS_ALPN: &[u8] = b"ntske/1";
pub const AEAD_AES_SIV_CMAC_256: u16 = 15;
const AEAD_KEY_LEN: usize = 32;
const EXPORTER_LABEL: &[u8] = b"EXPORTER-network-time-security";
/// RFC 8915 §6: clients should aim to hold eight cookies.
const COOKIE_POOL_TARGET: usize = 8;
const MAX_KE_RESPONSE: usize = 65536;

pub const EF_UNIQUE_ID: u16 = 0x0104;
pub const EF_COOKIE: u16 = 0x0204;
pub const EF_COOKIE_PLACEHOLDER: u16 = 0x0304;
pub const EF_AUTHENTICATOR: u16 = 0x0404;

pub const KE_END: u16 = 0;
pub const KE_NEXT_PROTOCOL: u16 = 1;
pub const KE_ERROR: u16 = 2;
pub const KE_WARNING: u16 = 3;
pub const KE_AEAD: u16 = 4;
pub const KE_COOKIE: u16 = 5;
pub const KE_SERVER: u16 = 6;
pub const KE_PORT: u16 = 7;

pub struct NtsSession {
    pub ke_host: String,
    pub ntp_host: String,
    pub ntp_port: u16,
    pub aead_id: u16,
    c2s_key: [u8; AEAD_KEY_LEN],
    s2c_key: [u8; AEAD_KEY_LEN],
    pub cookies: Vec<Vec<u8>>,
    pub tls_version: String,
    pub cipher: String,
    /// Non-fatal warning records sent by the server.
    pub warnings: Vec<u16>,
}

impl std::fmt::Debug for NtsSession {
    // Keys are deliberately omitted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtsSession")
            .field("ke_host", &self.ke_host)
            .field("ntp_host", &self.ntp_host)
            .field("ntp_port", &self.ntp_port)
            .field("cookies", &self.cookies.len())
            .finish_non_exhaustive()
    }
}

impl NtsSession {
    /// Build a session from already-derived keys (used by tests and alternative KE paths).
    pub fn from_keys(
        ntp_host: &str,
        ntp_port: u16,
        c2s: [u8; 32],
        s2c: [u8; 32],
        cookies: Vec<Vec<u8>>,
    ) -> Self {
        NtsSession {
            ke_host: ntp_host.to_string(),
            ntp_host: ntp_host.to_string(),
            ntp_port,
            aead_id: AEAD_AES_SIV_CMAC_256,
            c2s_key: c2s,
            s2c_key: s2c,
            cookies,
            tls_version: String::new(),
            cipher: String::new(),
            warnings: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// NTS-KE records

pub fn make_ke_record(record_type: u16, body: &[u8], critical: bool) -> Vec<u8> {
    assert!(record_type <= 0x7FFF, "invalid NTS-KE record type");
    let wire = record_type | if critical { 0x8000 } else { 0 };
    let mut v = Vec::with_capacity(4 + body.len());
    v.extend_from_slice(&wire.to_be_bytes());
    v.extend_from_slice(&(body.len() as u16).to_be_bytes());
    v.extend_from_slice(body);
    v
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeRecord {
    pub record_type: u16,
    pub critical: bool,
    pub body: Vec<u8>,
}

pub fn parse_ke_records(data: &[u8]) -> Result<Vec<KeRecord>, ProtocolError> {
    let mut records = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let wire = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + len > data.len() {
            return Err(ProtocolError::new("truncated NTS-KE record"));
        }
        let rec = KeRecord {
            record_type: wire & 0x7FFF,
            critical: wire & 0x8000 != 0,
            body: data[pos..pos + len].to_vec(),
        };
        pos += len;
        if rec.record_type == KE_END {
            if len != 0 || !rec.critical {
                return Err(ProtocolError::new("invalid End-of-Message record"));
            }
            if pos != data.len() {
                return Err(ProtocolError::new("data follows NTS-KE End-of-Message"));
            }
            records.push(rec);
            return Ok(records);
        }
        records.push(rec);
    }
    Err(ProtocolError::new(
        "NTS-KE response has no End-of-Message record",
    ))
}

pub fn ke_message_complete(data: &[u8]) -> bool {
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]) & 0x7FFF;
        let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4 + len;
        if pos > data.len() {
            return false;
        }
        if rtype == KE_END {
            return true;
        }
    }
    false
}

pub fn ke_request() -> Vec<u8> {
    let mut req = make_ke_record(KE_NEXT_PROTOCOL, &0u16.to_be_bytes(), true);
    req.extend(make_ke_record(
        KE_AEAD,
        &AEAD_AES_SIV_CMAC_256.to_be_bytes(),
        false,
    ));
    req.extend(make_ke_record(KE_END, &[], true));
    req
}

fn ke_error_name(code: u16) -> &'static str {
    match code {
        0 => "Unrecognized Critical Record",
        1 => "Bad Request",
        2 => "Internal Server Error",
        _ => "unknown",
    }
}

/// Result of interpreting the server's KE response records (before key export).
#[derive(Debug, PartialEq)]
pub struct KeNegotiation {
    pub aead_id: u16,
    pub cookies: Vec<Vec<u8>>,
    pub ntp_host: Option<String>,
    pub ntp_port: Option<u16>,
    pub warnings: Vec<u16>,
}

pub fn interpret_ke_response(records: &[KeRecord]) -> Result<KeNegotiation, ProtocolError> {
    let mut next_protocols = Vec::new();
    let mut aead = None;
    let mut neg = KeNegotiation {
        aead_id: 0,
        cookies: Vec::new(),
        ntp_host: None,
        ntp_port: None,
        warnings: Vec::new(),
    };
    for r in records {
        let u16_body = || (r.body.len() == 2).then(|| u16::from_be_bytes([r.body[0], r.body[1]]));
        match r.record_type {
            KE_NEXT_PROTOCOL => {
                if r.body.len() % 2 != 0 {
                    return Err(ProtocolError::new("malformed Next Protocol record"));
                }
                next_protocols.extend(r.body.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])));
            }
            KE_ERROR => {
                let code = u16_body()
                    .ok_or_else(|| ProtocolError::new("malformed NTS-KE Error record"))?;
                return Err(ProtocolError::new(format!(
                    "NTS-KE server returned error {code} ({})",
                    ke_error_name(code)
                )));
            }
            KE_WARNING => neg.warnings.push(u16_body().unwrap_or(u16::MAX)),
            KE_AEAD => {
                aead = Some(u16_body().ok_or_else(|| {
                    ProtocolError::new("server selected zero or multiple AEAD algorithms")
                })?);
            }
            KE_COOKIE => {
                if r.body.is_empty() {
                    return Err(ProtocolError::new("server returned an empty NTS cookie"));
                }
                neg.cookies.push(r.body.clone());
            }
            KE_SERVER => {
                let s = std::str::from_utf8(&r.body)
                    .ok()
                    .filter(|s| s.is_ascii() && !s.is_empty())
                    .ok_or_else(|| {
                        ProtocolError::new("malformed NTPv4 Server Negotiation record")
                    })?;
                neg.ntp_host = Some(s.trim_end_matches('.').to_string());
            }
            KE_PORT => {
                neg.ntp_port = Some(u16_body().ok_or_else(|| {
                    ProtocolError::new("malformed NTPv4 Port Negotiation record")
                })?);
            }
            KE_END => {}
            other if r.critical => {
                return Err(ProtocolError::new(format!(
                    "unknown critical NTS-KE record type {other}"
                )));
            }
            _ => {}
        }
    }
    if !next_protocols.contains(&0) {
        return Err(ProtocolError::new(
            "server did not negotiate NTPv4 as the next protocol",
        ));
    }
    match aead {
        Some(AEAD_AES_SIV_CMAC_256) => neg.aead_id = AEAD_AES_SIV_CMAC_256,
        other => {
            return Err(ProtocolError::new(format!(
                "unsupported AEAD selected by server: {other:?}"
            )));
        }
    }
    if neg.cookies.is_empty() {
        return Err(ProtocolError::new("NTS-KE server returned no cookies"));
    }
    Ok(neg)
}

// ---------------------------------------------------------------------------
// TLS

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Trust anchors: the Mozilla root set plus the OS certificate store, so that a
/// private CA installed on this machine (e.g. for a lab NTS server) is honoured.
fn root_store() -> RootCertStore {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    roots
}

#[derive(Debug)]
struct NoVerification(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

pub fn tls_config(skip_verify: bool) -> Result<Arc<ClientConfig>, ProtocolError> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ProtocolError::new(format!("TLS configuration error: {e}")))?;
    let mut cfg = if skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerification(
                provider.signature_verification_algorithms,
            )))
            .with_no_client_auth()
    } else {
        builder
            .with_root_certificates(root_store())
            .with_no_client_auth()
    };
    cfg.alpn_protocols = vec![NTS_ALPN.to_vec()];
    Ok(Arc::new(cfg))
}

fn remaining(deadline: Instant) -> Result<Duration, ProtocolError> {
    let now = Instant::now();
    if now >= deadline {
        return Err(ProtocolError::new("NTS-KE timed out"));
    }
    Ok(deadline - now)
}

fn io_err(context: &str, e: io::Error) -> ProtocolError {
    match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => {
            ProtocolError::new(format!("NTS-KE timed out during {context}"))
        }
        _ => {
            let mut msg = format!("NTS-KE {context} failed: {e}");
            if let Some(inner) = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>())
                && matches!(inner, rustls::Error::InvalidCertificate(_))
            {
                msg.push_str(" (connect by the name on the certificate; for a self-signed or private-CA server install its CA in the Windows certificate store, or enable 'Skip TLS certificate verification' for lab use)");
            }
            ProtocolError::new(msg)
        }
    }
}

/// Drive the connection until `done` returns true, honouring an overall deadline.
fn pump(
    conn: &mut ClientConnection,
    tcp: &mut TcpStream,
    deadline: Instant,
    context: &str,
    mut done: impl FnMut(&mut ClientConnection) -> bool,
) -> Result<bool, ProtocolError> {
    while !done(conn) {
        let left = remaining(deadline)?;
        tcp.set_read_timeout(Some(left)).ok();
        tcp.set_write_timeout(Some(left)).ok();
        let (rd, wr) = conn.complete_io(tcp).map_err(|e| io_err(context, e))?;
        if rd == 0 && wr == 0 {
            return Ok(false); // peer closed
        }
    }
    Ok(true)
}

/// Split `host`, `host:port`, `[v6]:port` or a bare IPv6 literal.
pub fn split_host_port(target: &str, default_port: u16) -> Result<(String, u16), ProtocolError> {
    let t = target.trim();
    if t.is_empty() {
        return Err(ProtocolError::new("server is empty"));
    }
    if let Some(rest) = t.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| ProtocolError::new("unterminated '[' in server address"))?;
        let port = match after.strip_prefix(':') {
            Some(p) => p
                .parse()
                .map_err(|_| ProtocolError::new(format!("invalid port '{p}'")))?,
            None if after.is_empty() => default_port,
            None => return Err(ProtocolError::new("unexpected text after ']'")),
        };
        return Ok((host.to_string(), port));
    }
    if t.parse::<IpAddr>().is_ok() {
        return Ok((t.to_string(), default_port));
    }
    match t.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => {
            let port = p
                .parse()
                .map_err(|_| ProtocolError::new(format!("invalid port '{p}'")))?;
            Ok((h.to_string(), port))
        }
        _ => Ok((t.to_string(), default_port)),
    }
}

/// Perform NTS Key Establishment against `host:port` (RFC 8915 §4).
pub fn perform_ke(
    host: &str,
    port: u16,
    skip_verify: bool,
    timeout: Duration,
) -> Result<NtsSession, ProtocolError> {
    let deadline = Instant::now() + timeout;
    let host_clean = host.trim_end_matches('.');
    let server_name = ServerName::try_from(host_clean.to_string()).map_err(|_| {
        ProtocolError::new(format!("'{host}' is not a valid DNS name or IP address"))
    })?;
    let config = tls_config(skip_verify)?;

    let addrs: Vec<_> = (host_clean, port)
        .to_socket_addrs()
        .map_err(|e| ProtocolError::new(format!("cannot resolve {host}: {e}")))?
        .collect();
    let mut last_err = None;
    let mut tcp = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, remaining(deadline)?) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last_err = Some(format!("{addr}: {e}")),
        }
    }
    let mut tcp = tcp.ok_or_else(|| {
        ProtocolError::new(format!(
            "TCP connect to {host}:{port} failed: {}",
            last_err.unwrap_or_else(|| "no addresses".into())
        ))
    })?;
    tcp.set_nodelay(true).ok();

    let mut conn = ClientConnection::new(config, server_name)
        .map_err(|e| ProtocolError::new(format!("TLS setup failed: {e}")))?;

    if !pump(&mut conn, &mut tcp, deadline, "TLS handshake", |c| {
        !c.is_handshaking()
    })? {
        return Err(ProtocolError::new(
            "server closed the connection during the TLS handshake",
        ));
    }
    if conn.alpn_protocol() != Some(NTS_ALPN) {
        let got = conn
            .alpn_protocol()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .unwrap_or_else(|| "none".into());
        return Err(ProtocolError::new(format!(
            "server did not negotiate required ALPN ntske/1 (got {got})"
        )));
    }

    conn.writer()
        .write_all(&ke_request())
        .map_err(|e| io_err("send", e))?;
    pump(&mut conn, &mut tcp, deadline, "send", |c| !c.wants_write())?;

    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let mut closed = false;
        loop {
            match conn.reader().read(&mut buf) {
                Ok(0) => {
                    closed = true;
                    break;
                }
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    closed = true;
                    break;
                }
                Err(e) => return Err(io_err("receive", e)),
            }
        }
        if ke_message_complete(&response) {
            break;
        }
        if response.len() > MAX_KE_RESPONSE {
            return Err(ProtocolError::new("NTS-KE response exceeds 64 KiB"));
        }
        if closed {
            return Err(ProtocolError::new(format!(
                "incomplete NTS-KE response ({} bytes before close)",
                response.len()
            )));
        }
        let left = remaining(deadline)?;
        tcp.set_read_timeout(Some(left)).ok();
        // On EOF this returns 0 and the reader reports the close on the next pass.
        conn.complete_io(&mut tcp)
            .map_err(|e| io_err("receive", e))?;
    }

    let neg = interpret_ke_response(&parse_ke_records(&response)?)?;

    let mut c2s_ctx = [0u8; 5];
    c2s_ctx[2..4].copy_from_slice(&neg.aead_id.to_be_bytes());
    let mut s2c_ctx = c2s_ctx;
    s2c_ctx[4] = 1;
    let c2s_key = conn
        .export_keying_material([0u8; AEAD_KEY_LEN], EXPORTER_LABEL, Some(&c2s_ctx))
        .map_err(|e| ProtocolError::new(format!("TLS exporter failed: {e}")))?;
    let s2c_key = conn
        .export_keying_material([0u8; AEAD_KEY_LEN], EXPORTER_LABEL, Some(&s2c_ctx))
        .map_err(|e| ProtocolError::new(format!("TLS exporter failed: {e}")))?;

    let tls_version = conn
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_default()
        .replace("TLSv1_3", "TLSv1.3");
    let cipher = conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_default();

    conn.send_close_notify();
    tcp.set_write_timeout(Some(Duration::from_millis(250))).ok();
    let _ = conn.complete_io(&mut tcp);

    Ok(NtsSession {
        ke_host: host_clean.to_string(),
        ntp_host: neg.ntp_host.unwrap_or_else(|| host_clean.to_string()),
        ntp_port: neg.ntp_port.unwrap_or(ntp::DEFAULT_NTP_PORT),
        aead_id: neg.aead_id,
        c2s_key,
        s2c_key,
        cookies: neg.cookies,
        tls_version,
        cipher,
        warnings: neg.warnings,
    })
}

// ---------------------------------------------------------------------------
// Authenticated NTP

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS random number generator unavailable");
    b
}

pub struct NtsRequest {
    pub packet: Vec<u8>,
    pub t1: NtpTimestamp,
    pub uid: [u8; 32],
    pub placeholders: usize,
}

/// Build an NTS-protected client request, consuming one cookie (RFC 8915 §5.7).
pub fn build_request(
    session: &mut NtsSession,
    t1: NtpTimestamp,
) -> Result<NtsRequest, ProtocolError> {
    if session.cookies.is_empty() {
        return Err(ProtocolError::new(
            "no unused NTS cookies remain; repeat NTS-KE",
        ));
    }
    let cookie = session.cookies.remove(0);
    if !cookie.len().is_multiple_of(4) {
        return Err(ProtocolError::new(
            "server supplied an NTS cookie that is not 32-bit aligned",
        ));
    }
    let uid = random::<32>();
    let mut pkt = ntp::build_client_request(t1).to_vec();
    pkt.extend(ntp::make_extension(EF_UNIQUE_ID, &uid)?);
    pkt.extend(ntp::make_extension(EF_COOKIE, &cookie)?);
    // The reply carries one cookie for the one we spent plus one per placeholder.
    let placeholders = COOKIE_POOL_TARGET
        .saturating_sub(session.cookies.len() + 1)
        .min(7);
    let zeros = vec![0u8; cookie.len()];
    for _ in 0..placeholders {
        pkt.extend(ntp::make_extension(EF_COOKIE_PLACEHOLDER, &zeros)?);
    }
    let nonce = random::<16>();
    let mut siv = Aes128Siv::new_from_slice(&session.c2s_key).expect("32-byte key");
    let ciphertext = siv
        .encrypt([pkt.as_slice(), &nonce[..]], &[])
        .map_err(|_| ProtocolError::new("AES-SIV encryption failed"))?;
    pkt.extend(ntp::make_extension(
        EF_AUTHENTICATOR,
        &authenticator_body(&nonce, &ciphertext),
    )?);
    Ok(NtsRequest {
        packet: pkt,
        t1,
        uid,
        placeholders,
    })
}

pub fn authenticator_body(nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    body.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    body.extend_from_slice(nonce);
    pad4(&mut body);
    body.extend_from_slice(ciphertext);
    pad4(&mut body);
    body
}

pub fn decode_authenticator(body: &[u8]) -> Result<(&[u8], &[u8]), ProtocolError> {
    if body.len() < 4 {
        return Err(ProtocolError::new("truncated NTS authenticator"));
    }
    let nonce_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let ct_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let nonce_pad = (nonce_len + 3) & !3;
    let ct_pad = (ct_len + 3) & !3;
    if 4 + nonce_pad + ct_pad > body.len() {
        return Err(ProtocolError::new("invalid NTS authenticator lengths"));
    }
    let ct_start = 4 + nonce_pad;
    Ok((&body[4..4 + nonce_len], &body[ct_start..ct_start + ct_len]))
}

#[derive(Debug)]
pub struct NtsResponse {
    pub ntp: NtpResponse,
    pub authenticated: bool,
    pub new_cookies: usize,
}

/// Validate and authenticate an NTS-protected server reply, adding any fresh
/// cookies to the session pool.
pub fn validate_response(
    data: &[u8],
    session: &mut NtsSession,
    req: &NtsRequest,
    t4: NtpTimestamp,
) -> Result<NtsResponse, ProtocolError> {
    let ntp = ntp::validate_response(data, req.t1, t4)?;
    let fields = ntp::parse_extensions(data, ntp::NTP_HEADER_LEN)?;

    let uid = fields
        .iter()
        .find(|f| f.field_type == EF_UNIQUE_ID)
        .map(|f| f.body);
    let mut auths = fields.iter().filter(|f| f.field_type == EF_AUTHENTICATOR);
    let auth = auths.next();
    if auths.next().is_some() {
        return Err(ProtocolError::new(
            "multiple NTS authenticator fields in response",
        ));
    }
    if uid != Some(&req.uid[..]) {
        return Err(ProtocolError::new("NTS Unique Identifier mismatch"));
    }

    let Some(auth) = auth else {
        if ntp.is_kod() {
            // RFC 8915 §5.7: an NTSN KoD is unauthenticated by design; other
            // unauthenticated KoDs must not be acted on, but we still report them.
            return Ok(NtsResponse {
                ntp,
                authenticated: false,
                new_cookies: 0,
            });
        }
        return Err(ProtocolError::new(
            "NTS-protected request received an unauthenticated response",
        ));
    };

    let (nonce, ciphertext) = decode_authenticator(auth.body)?;
    let mut siv = Aes128Siv::new_from_slice(&session.s2c_key).expect("32-byte key");
    let plaintext = siv
        .decrypt([&data[..auth.start], nonce], ciphertext)
        .map_err(|_| ProtocolError::new("NTS response authentication failed (S2C tag mismatch)"))?;

    let mut new_cookies = 0;
    for f in ntp::parse_extensions(&plaintext, 0)? {
        if f.field_type == EF_COOKIE {
            session.cookies.push(f.body.to_vec());
            new_cookies += 1;
        }
    }
    Ok(NtsResponse {
        ntp,
        authenticated: true,
        new_cookies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ke_request_layout() {
        let r = ke_request();
        assert_eq!(r, [0x80, 1, 0, 2, 0, 0, 0, 4, 0, 2, 0, 15, 0x80, 0, 0, 0]);
        assert!(ke_message_complete(&r));
        assert!(!ke_message_complete(&r[..r.len() - 1]));
        assert_eq!(parse_ke_records(&r).unwrap().len(), 3);
    }

    fn ke_response(extra: &[Vec<u8>]) -> Vec<u8> {
        let mut r = make_ke_record(KE_NEXT_PROTOCOL, &[0, 0], true);
        r.extend(make_ke_record(KE_AEAD, &[0, 15], true));
        for e in extra {
            r.extend_from_slice(e);
        }
        r.extend(make_ke_record(KE_END, &[], true));
        r
    }

    #[test]
    fn interprets_ke_response() {
        let r = ke_response(&[
            make_ke_record(KE_COOKIE, &[1; 100], false),
            make_ke_record(KE_COOKIE, &[2; 100], false),
            make_ke_record(KE_SERVER, b"ntp.example.", true),
            make_ke_record(KE_PORT, &[0x12, 0x34], true),
            make_ke_record(KE_WARNING, &[0, 9], true),
            make_ke_record(0x4000, b"ignored", false),
        ]);
        let n = interpret_ke_response(&parse_ke_records(&r).unwrap()).unwrap();
        assert_eq!(n.cookies.len(), 2);
        assert_eq!(n.ntp_host.as_deref(), Some("ntp.example"));
        assert_eq!(n.ntp_port, Some(0x1234));
        assert_eq!(n.warnings, vec![9]);
    }

    #[test]
    fn rejects_bad_ke_responses() {
        let no_cookie = ke_response(&[]);
        assert!(interpret_ke_response(&parse_ke_records(&no_cookie).unwrap()).is_err());
        let err = ke_response(&[make_ke_record(KE_ERROR, &[0, 1], true)]);
        assert!(
            interpret_ke_response(&parse_ke_records(&err).unwrap())
                .unwrap_err()
                .to_string()
                .contains("Bad Request")
        );
        let crit = ke_response(&[
            make_ke_record(KE_COOKIE, &[1; 4], false),
            make_ke_record(0x4000, b"", true),
        ]);
        assert!(interpret_ke_response(&parse_ke_records(&crit).unwrap()).is_err());
        let mut trailing = ke_response(&[]);
        trailing.push(0);
        assert!(parse_ke_records(&trailing).is_err());
    }

    #[test]
    fn host_port_parsing() {
        let p = |s| split_host_port(s, 4460).unwrap();
        assert_eq!(
            p("time.cloudflare.com"),
            ("time.cloudflare.com".into(), 4460)
        );
        assert_eq!(p("10.0.0.5:1234"), ("10.0.0.5".into(), 1234));
        assert_eq!(p("2001:db8::1"), ("2001:db8::1".into(), 4460));
        assert_eq!(p("[2001:db8::1]:99"), ("2001:db8::1".into(), 99));
        assert_eq!(p("[::1]"), ("::1".into(), 4460));
        assert!(split_host_port("host:notaport", 1).is_err());
        assert!(split_host_port("  ", 1).is_err());
    }

    /// Simulate the server side with the same keys and check the full
    /// request → authenticated reply → cookie replenishment cycle.
    #[test]
    fn authenticated_roundtrip() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let mut session =
            NtsSession::from_keys("127.0.0.1", 123, c2s, s2c, vec![vec![0xAB; 64]; 8]);
        let t1 = NtpTimestamp::now();
        let req = build_request(&mut session, t1).unwrap();
        assert_eq!(session.cookies.len(), 7);
        assert_eq!(req.placeholders, 0);

        // Server: verify the client authenticator with C2S.
        let fields = ntp::parse_extensions(&req.packet, 48).unwrap();
        let auth = fields
            .iter()
            .find(|f| f.field_type == EF_AUTHENTICATOR)
            .unwrap();
        assert_eq!(auth.end, req.packet.len());
        let (nonce, ct) = decode_authenticator(auth.body).unwrap();
        Aes128Siv::new_from_slice(&c2s)
            .unwrap()
            .decrypt([&req.packet[..auth.start], nonce], ct)
            .unwrap();

        // Server reply: header + UID + authenticator with one encrypted cookie.
        let mut reply = vec![0u8; 48];
        reply[0] = 0x24;
        reply[1] = 1;
        reply[12..16].copy_from_slice(b"GPS\0");
        reply[24..32].copy_from_slice(&t1.to_bytes());
        reply[32..40].copy_from_slice(&t1.add_secs(0.001).to_bytes());
        reply[40..48].copy_from_slice(&t1.add_secs(0.002).to_bytes());
        reply.extend(ntp::make_extension(EF_UNIQUE_ID, &req.uid).unwrap());
        let plaintext = ntp::make_extension(EF_COOKIE, &[0xCD; 64]).unwrap();
        let snonce = [7u8; 16];
        let sct = Aes128Siv::new_from_slice(&s2c)
            .unwrap()
            .encrypt([reply.as_slice(), &snonce[..]], &plaintext)
            .unwrap();
        reply.extend(
            ntp::make_extension(EF_AUTHENTICATOR, &authenticator_body(&snonce, &sct)).unwrap(),
        );

        let t4 = t1.add_secs(0.003);
        let r = validate_response(&reply, &mut session, &req, t4).unwrap();
        assert!(r.authenticated);
        assert_eq!(r.new_cookies, 1);
        assert_eq!(session.cookies.len(), 8);
        assert_eq!(r.ntp.ref_id_display(), "GPS");

        // Tampering with any authenticated byte must fail.
        let mut bad = reply.clone();
        bad[45] ^= 0x01;
        let req2_uid_ok = validate_response(&bad, &mut session, &req, t4);
        assert!(
            req2_uid_ok
                .unwrap_err()
                .to_string()
                .contains("authentication failed")
        );

        // A wrong UID must fail.
        let mut wrong_uid = reply.clone();
        wrong_uid[52] ^= 0xFF;
        assert!(
            validate_response(&wrong_uid, &mut session, &req, t4)
                .unwrap_err()
                .to_string()
                .contains("Unique Identifier")
        );
    }

    #[test]
    fn placeholders_refill_pool() {
        let mut s = NtsSession::from_keys("h", 123, [0; 32], [0; 32], vec![vec![0; 8]; 3]);
        let req = build_request(&mut s, NtpTimestamp::now()).unwrap();
        assert_eq!(req.placeholders, 5); // 2 left + 1 replacement + 5 placeholders = 8
        let n = ntp::parse_extensions(&req.packet, 48)
            .unwrap()
            .iter()
            .filter(|f| f.field_type == EF_COOKIE_PLACEHOLDER)
            .count();
        assert_eq!(n, 5);
    }
}
