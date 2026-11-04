//! NTPv4 packet construction and validation (RFC 5905, RFC 7822).

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ProtocolError;

/// Seconds between the NTP era-0 epoch (1900-01-01) and the Unix epoch.
pub const NTP_UNIX_OFFSET: u64 = 2_208_988_800;
pub const NTP_HEADER_LEN: usize = 48;
pub const DEFAULT_NTP_PORT: u16 = 123;

/// A 64-bit NTP timestamp (32.32 fixed point seconds since 1900, modulo era).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NtpTimestamp(pub u64);

impl NtpTimestamp {
    pub const ZERO: NtpTimestamp = NtpTimestamp(0);

    pub fn now() -> Self {
        Self::from_system_time(SystemTime::now())
    }

    pub fn from_system_time(t: SystemTime) -> Self {
        let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = d.as_secs().wrapping_add(NTP_UNIX_OFFSET) & 0xFFFF_FFFF;
        let frac = ((d.subsec_nanos() as u64) << 32) / 1_000_000_000;
        NtpTimestamp((secs << 32) | frac)
    }

    pub fn from_bytes(b: &[u8]) -> Self {
        NtpTimestamp(u64::from_be_bytes(b[..8].try_into().unwrap()))
    }

    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Shift by a signed number of seconds.
    pub fn add_secs(self, secs: f64) -> Self {
        let delta = (secs * 4_294_967_296.0).round() as i64;
        NtpTimestamp(self.0.wrapping_add(delta as u64))
    }

    /// `self - other` in seconds, computed in wrapping fixed point so that the
    /// result is exact and correct across an NTP era rollover (RFC 5905 §6).
    pub fn diff_secs(self, other: NtpTimestamp) -> f64 {
        (self.0.wrapping_sub(other.0) as i64) as f64 / 4_294_967_296.0
    }

    /// Unix time in seconds, assuming the current NTP era (valid until 2036).
    pub fn to_unix_secs(self) -> f64 {
        (self.0 >> 32) as f64 - NTP_UNIX_OFFSET as f64
            + (self.0 & 0xFFFF_FFFF) as f64 / 4_294_967_296.0
    }
}

/// Build a 48-byte NTPv4 client request (LI=0, VN=4, Mode=3) with the given transmit time.
pub fn build_client_request(t1: NtpTimestamp) -> [u8; NTP_HEADER_LEN] {
    let mut p = [0u8; NTP_HEADER_LEN];
    p[0] = 0x23;
    p[40..48].copy_from_slice(&t1.to_bytes());
    p
}

/// NTP short format (16.16) to seconds.
fn short_to_secs(b: &[u8]) -> f64 {
    u32::from_be_bytes(b[..4].try_into().unwrap()) as f64 / 65536.0
}

#[derive(Clone, Debug, PartialEq)]
pub struct NtpResponse {
    pub leap: u8,
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay_ms: f64,
    pub root_dispersion_ms: f64,
    pub ref_id: [u8; 4],
    /// Kiss code when stratum == 0.
    pub kiss_code: Option<String>,
    pub timing: Option<Timing>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Timing {
    pub offset_ms: f64,
    pub delay_ms: f64,
    /// Server processing time (T3 - T2).
    pub server_ms: f64,
}

impl NtpResponse {
    pub fn is_kod(&self) -> bool {
        self.stratum == 0
    }

    /// Human readable reference ID: ASCII for stratum 0/1, IPv4 dotted quad otherwise.
    pub fn ref_id_display(&self) -> String {
        if self.stratum <= 1 {
            let s: String = self
                .ref_id
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| if b.is_ascii_graphic() { b as char } else { '?' })
                .collect();
            s
        } else {
            let [a, b, c, d] = self.ref_id;
            format!("{a}.{b}.{c}.{d}")
        }
    }

    /// Conditions that are legal on the wire but mean the time should not be trusted.
    pub fn warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        // A Kiss-o'-Death carries LI=3 by definition (RFC 5905 §7.4); it is reported separately.
        if self.is_kod() {
            return w;
        }
        if self.leap == 3 {
            w.push("LI=3: server clock is unsynchronized (alarm condition)".to_string());
        }
        if self.stratum >= 16 {
            w.push(format!("stratum {} means unsynchronized", self.stratum));
        }
        if self.root_dispersion_ms > 1000.0 {
            w.push(format!(
                "root dispersion {:.1} ms exceeds 1 s",
                self.root_dispersion_ms
            ));
        }
        if self.version == 3 {
            w.push("server answered with NTPv3".to_string());
        }
        w
    }
}

impl fmt::Display for NtpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LI={} VN={} Mode={} Stratum={} Poll={} Precision=2^{} RefID={} RootDelay={:.3} ms RootDisp={:.3} ms",
            self.leap,
            self.version,
            self.mode,
            self.stratum,
            self.poll,
            self.precision,
            self.ref_id_display(),
            self.root_delay_ms,
            self.root_dispersion_ms
        )
    }
}

/// Validate an NTP server response against the request that produced it.
pub fn validate_response(
    data: &[u8],
    t1: NtpTimestamp,
    t4: NtpTimestamp,
) -> Result<NtpResponse, ProtocolError> {
    if data.len() < NTP_HEADER_LEN {
        return Err(ProtocolError::new(format!(
            "short NTP response ({} bytes)",
            data.len()
        )));
    }
    let leap = data[0] >> 6;
    let version = (data[0] >> 3) & 0x7;
    let mode = data[0] & 0x7;
    if mode != 4 {
        return Err(ProtocolError::new(format!(
            "unexpected NTP mode {mode}; expected server mode 4"
        )));
    }
    if !(3..=4).contains(&version) {
        return Err(ProtocolError::new(format!(
            "unexpected NTP version {version}"
        )));
    }
    if data[24..32] != t1.to_bytes() {
        return Err(ProtocolError::new(
            "originate timestamp does not match this request (possible spoof or stale reply)",
        ));
    }

    let stratum = data[1];
    let mut ref_id = [0u8; 4];
    ref_id.copy_from_slice(&data[12..16]);
    let mut resp = NtpResponse {
        leap,
        version,
        mode,
        stratum,
        poll: data[2] as i8,
        precision: data[3] as i8,
        root_delay_ms: short_to_secs(&data[4..8]) * 1000.0,
        root_dispersion_ms: short_to_secs(&data[8..12]) * 1000.0,
        ref_id,
        kiss_code: None,
        timing: None,
    };
    if stratum == 0 {
        resp.kiss_code = Some(String::from_utf8_lossy(&ref_id).into_owned());
        return Ok(resp);
    }

    let t2 = NtpTimestamp::from_bytes(&data[32..40]);
    let t3 = NtpTimestamp::from_bytes(&data[40..48]);
    if t2 == NtpTimestamp::ZERO || t3 == NtpTimestamp::ZERO {
        return Err(ProtocolError::new(
            "server returned a zero receive/transmit timestamp",
        ));
    }
    let offset = (t2.diff_secs(t1) + t3.diff_secs(t4)) / 2.0;
    let delay = t4.diff_secs(t1) - t3.diff_secs(t2);
    resp.timing = Some(Timing {
        offset_ms: offset * 1000.0,
        delay_ms: delay * 1000.0,
        server_ms: t3.diff_secs(t2) * 1000.0,
    });
    Ok(resp)
}

/// Build an NTP extension field (RFC 7822). `body` must keep the field 32-bit aligned.
pub fn make_extension(field_type: u16, body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let total = 4 + body.len();
    if !total.is_multiple_of(4) {
        return Err(ProtocolError::new(format!(
            "extension 0x{field_type:04x} body is not 32-bit aligned"
        )));
    }
    if total > 0xFFFF {
        return Err(ProtocolError::new("NTP extension field too large"));
    }
    let mut v = Vec::with_capacity(total);
    v.extend_from_slice(&field_type.to_be_bytes());
    v.extend_from_slice(&(total as u16).to_be_bytes());
    v.extend_from_slice(body);
    Ok(v)
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExtField<'a> {
    pub field_type: u16,
    pub body: &'a [u8],
    pub start: usize,
    pub end: usize,
}

/// Parse extension fields starting at `start` until the end of `data`.
pub fn parse_extensions(data: &[u8], start: usize) -> Result<Vec<ExtField<'_>>, ProtocolError> {
    let mut fields = Vec::new();
    let mut pos = start;
    while pos < data.len() {
        if data.len() - pos < 4 {
            return Err(ProtocolError::new(
                "trailing bytes after NTP extension fields",
            ));
        }
        let field_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        if len < 4 || !len.is_multiple_of(4) || pos + len > data.len() {
            return Err(ProtocolError::new(format!(
                "invalid NTP extension field length {len}"
            )));
        }
        fields.push(ExtField {
            field_type,
            body: &data[pos + 4..pos + len],
            start: pos,
            end: pos + len,
        });
        pos += len;
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn timestamp_roundtrip_and_diff() {
        let t = SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 500_000_000);
        let ts = NtpTimestamp::from_system_time(t);
        assert_eq!(ts.0 >> 32, 1_700_000_000 + NTP_UNIX_OFFSET);
        assert_eq!(ts.0 & 0xFFFF_FFFF, 0x8000_0000);
        assert!((ts.to_unix_secs() - 1_700_000_000.5).abs() < 1e-6);
        let later = ts.add_secs(0.25);
        assert!((later.diff_secs(ts) - 0.25).abs() < 1e-9);
        assert!((ts.diff_secs(later) + 0.25).abs() < 1e-9);
    }

    #[test]
    fn diff_across_era_rollover() {
        let before = NtpTimestamp(0xFFFF_FFFF_8000_0000); // era 0, last half second
        let after = NtpTimestamp(0x0000_0000_8000_0000); // era 1, first half second
        assert!((after.diff_secs(before) - 1.0).abs() < 1e-9);
    }

    fn server_reply(t1: NtpTimestamp, t2: NtpTimestamp, t3: NtpTimestamp) -> [u8; 48] {
        let mut r = [0u8; 48];
        r[0] = 0x24;
        r[1] = 2;
        r[12..16].copy_from_slice(&[192, 0, 2, 1]);
        r[24..32].copy_from_slice(&t1.to_bytes());
        r[32..40].copy_from_slice(&t2.to_bytes());
        r[40..48].copy_from_slice(&t3.to_bytes());
        r
    }

    #[test]
    fn offset_and_delay() {
        let t1 = NtpTimestamp::now();
        // Server clock 50 ms ahead, 10 ms each way, 2 ms processing.
        let t2 = t1.add_secs(0.060);
        let t3 = t2.add_secs(0.002);
        let t4 = t1.add_secs(0.022);
        let r = validate_response(&server_reply(t1, t2, t3), t1, t4).unwrap();
        let timing = r.timing.unwrap();
        assert!((timing.offset_ms - 50.0).abs() < 1e-3, "{timing:?}");
        assert!((timing.delay_ms - 20.0).abs() < 1e-3);
        assert!((timing.server_ms - 2.0).abs() < 1e-3);
        assert_eq!(r.ref_id_display(), "192.0.2.1");
    }

    #[test]
    fn rejects_bad_responses() {
        let t1 = NtpTimestamp::now();
        let good = server_reply(t1, t1, t1);
        assert!(validate_response(&good[..40], t1, t1).is_err());
        let mut m = good;
        m[0] = 0x23;
        assert!(validate_response(&m, t1, t1).is_err());
        let mut m = good;
        m[24] ^= 1;
        assert!(validate_response(&m, t1, t1).is_err());
        let mut m = good;
        m[32..40].fill(0);
        assert!(validate_response(&m, t1, t1).is_err());
        let mut m = good;
        m[1] = 0;
        m[12..16].copy_from_slice(b"RATE");
        assert_eq!(
            validate_response(&m, t1, t1).unwrap().kiss_code.as_deref(),
            Some("RATE")
        );
        m[0] = 0xE4; // KoD packets carry LI=3
        assert!(validate_response(&m, t1, t1).unwrap().warnings().is_empty());
    }

    #[test]
    fn extensions_roundtrip() {
        let mut pkt = vec![0u8; 48];
        pkt.extend(make_extension(0x0104, &[7u8; 32]).unwrap());
        pkt.extend(make_extension(0x0204, &[9u8; 8]).unwrap());
        let f = parse_extensions(&pkt, 48).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].field_type, 0x0104);
        assert_eq!(f[1].body, &[9u8; 8]);
        assert!(make_extension(1, &[0u8; 3]).is_err());
        pkt.push(0);
        assert!(parse_extensions(&pkt, 48).is_err());
    }
}
