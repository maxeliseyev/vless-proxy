//! XTLS Vision flow control (`xtls-rprx-vision`), ported from Xray-core
//! `proxy/proxy.go` (`VisionReader`, `VisionWriter`, `XtlsPadding`,
//! `XtlsUnpadding`, `XtlsFilterTls`).
//!
//! Vision does two things on top of a VLESS session carried inside an outer
//! TLS/REALITY tunnel:
//!
//! 1. While the inner connection is still handshaking, every chunk is wrapped
//!    in a padding block `[uuid once][cmd][content_len][padding_len][content][zeros]`
//!    so the outer record lengths do not betray the inner TLS handshake.
//! 2. Once both sides have seen an inner TLS 1.3 handshake, each direction
//!    sends a final block with [`CMD_DIRECT`] and from then on copies the inner
//!    TLS records straight onto the TCP socket, skipping the outer encryption.
//!
//! This module is pure state and byte manipulation; the stream plumbing lives
//! in [`crate::protocol::vless::VlessStream`].

use rand::Rng;

pub const BUF_SIZE: usize = 8192;
/// Bytes a padding block adds on top of its content (16 uuid + 5 header).
pub const PADDING_OVERHEAD: usize = 21;
pub const MAX_CONTENT: usize = BUF_SIZE - PADDING_OVERHEAD;

pub const CMD_CONTINUE: u8 = 0x00;
pub const CMD_END: u8 = 0x01;
pub const CMD_DIRECT: u8 = 0x02;

pub const FLOW_VISION: &str = "xtls-rprx-vision";
pub const FLOW_VISION_UDP443: &str = "xtls-rprx-vision-udp443";

const TLS13_SUPPORTED_VERSIONS: &[u8] = &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS_CLIENT_HANDSHAKE_START: &[u8] = &[0x16, 0x03];
const TLS_SERVER_HANDSHAKE_START: &[u8] = &[0x16, 0x03, 0x03];
const TLS_APPLICATION_DATA_START: &[u8] = &[0x17, 0x03, 0x03];
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;

/// Xray `MemoryAccount.Testseed` defaults: `[900, 500, 900, 256]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaddingSeed(pub [u32; 4]);

impl Default for PaddingSeed {
    fn default() -> Self {
        Self([900, 500, 900, 256])
    }
}

/// Inner-traffic classifier shared by both directions (`TrafficState` minus
/// the per-direction padding counters).
#[derive(Debug, Clone)]
pub struct TrafficFilter {
    pub packets_to_filter: i32,
    pub is_tls: bool,
    pub is_tls12_or_above: bool,
    pub cipher: u16,
    pub remaining_server_hello: i32,
    pub enable_xtls: bool,
}

impl Default for TrafficFilter {
    fn default() -> Self {
        Self {
            packets_to_filter: 8,
            is_tls: false,
            is_tls12_or_above: false,
            cipher: 0,
            remaining_server_hello: -1,
            enable_xtls: false,
        }
    }
}

impl TrafficFilter {
    /// `XtlsFilterTls` for one buffer.
    pub fn filter(&mut self, b: &[u8]) {
        self.packets_to_filter -= 1;
        if b.len() >= 6 {
            if b[..3] == *TLS_SERVER_HANDSHAKE_START && b[5] == TLS_HANDSHAKE_SERVER_HELLO {
                self.remaining_server_hello = ((b[3] as i32) << 8 | b[4] as i32) + 5;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                if b.len() >= 79 && self.remaining_server_hello >= 79 {
                    let sid_len = b[43] as usize;
                    if b.len() >= 46 + sid_len {
                        self.cipher = (b[44 + sid_len] as u16) << 8 | b[45 + sid_len] as u16;
                    }
                }
            } else if b[..2] == *TLS_CLIENT_HANDSHAKE_START && b[5] == TLS_HANDSHAKE_CLIENT_HELLO {
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(b.len());
            self.remaining_server_hello -= b.len() as i32;
            if contains(&b[..end], TLS13_SUPPORTED_VERSIONS) {
                // TLS 1.3. Everything but AES-128-CCM-8 is eligible for direct copy.
                if (0x1301..=0x1304).contains(&self.cipher) {
                    self.enable_xtls = true;
                }
                self.packets_to_filter = 0;
            } else if self.remaining_server_hello <= 0 {
                // TLS 1.2 or older: keep padding, never go direct.
                self.packets_to_filter = 0;
            }
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// `IsCompleteRecord`: the buffer is a sequence of whole TLS application-data records.
pub fn is_complete_record(b: &[u8]) -> bool {
    let mut i = 0;
    while i < b.len() {
        if b.len() - i < 5 {
            return false;
        }
        if b[i..i + 3] != *TLS_APPLICATION_DATA_START {
            return false;
        }
        let len = (b[i + 3] as usize) << 8 | b[i + 4] as usize;
        if len == 0 {
            return false;
        }
        i += 5 + len;
    }
    i == b.len()
}

/// `ReshapeMultiBuffer` over Xray-sized windows: every piece is at most
/// [`MAX_CONTENT`] bytes so it fits one padding block.
pub fn reshape(data: &[u8]) -> Vec<&[u8]> {
    let mut pieces = Vec::new();
    for window in data.chunks(BUF_SIZE) {
        if window.len() >= MAX_CONTENT {
            let mut index = window
                .windows(3)
                .rposition(|w| w == TLS_APPLICATION_DATA_START)
                .unwrap_or(0);
            if !(PADDING_OVERHEAD..=MAX_CONTENT).contains(&index) {
                index = BUF_SIZE / 2;
            }
            pieces.push(&window[..index]);
            pieces.push(&window[index..]);
        } else {
            pieces.push(window);
        }
    }
    pieces
}

/// Uplink (writer) padding state: `OutboundState.IsPadding` + `writeOnceUserUUID`.
#[derive(Debug)]
pub struct Padder {
    uuid: Option<[u8; 16]>,
    pub is_padding: bool,
    seed: PaddingSeed,
}

impl Padder {
    pub fn new(uuid: [u8; 16], seed: PaddingSeed) -> Self {
        Self {
            uuid: Some(uuid),
            is_padding: true,
            seed,
        }
    }

    /// `XtlsPadding`: append one block wrapping `content` to `out`.
    pub fn pad(&mut self, content: &[u8], command: u8, long_padding: bool, out: &mut Vec<u8>) {
        debug_assert!(content.len() <= MAX_CONTENT);
        let content_len = content.len() as i64;
        let seed = self.seed.0;
        let mut rng = rand::thread_rng();
        let mut padding_len: i64 = if content_len < seed[0] as i64 && long_padding {
            rng.gen_range(0..seed[1] as i64) + seed[2] as i64 - content_len
        } else {
            rng.gen_range(0..seed[3] as i64)
        };
        padding_len = padding_len.min(MAX_CONTENT as i64 - content_len).max(0);

        if let Some(uuid) = self.uuid.take() {
            out.extend_from_slice(&uuid);
        }
        out.push(command);
        out.extend_from_slice(&(content_len as u16).to_be_bytes());
        out.extend_from_slice(&(padding_len as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + padding_len as usize, 0);
    }
}

/// Downlink (reader) unpadding state: the `Outbound.*` reader fields of `TrafficState`.
#[derive(Debug)]
pub struct Unpadder {
    uuid: [u8; 16],
    pub within_padding: bool,
    remaining_command: i32,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: i32,
    /// Bytes held back while waiting to see whether a block starts (Xray
    /// decides on whole records; we may get smaller reads).
    head: Vec<u8>,
}

impl Unpadder {
    pub fn new(uuid: [u8; 16]) -> Self {
        Self {
            uuid,
            within_padding: true,
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            head: Vec::new(),
        }
    }

    /// `XtlsUnpadding` for one buffer: content bytes go to `out`.
    pub fn unpad(&mut self, b: &[u8], out: &mut Vec<u8>) {
        if self.remaining_command == -1
            && self.remaining_content == -1
            && self.remaining_padding == -1
        {
            if !self.head.is_empty() || (self.within_padding && b.len() < PADDING_OVERHEAD) {
                // Not enough to tell a block from plain data yet.
                self.head.extend_from_slice(b);
                if self.head.len() < PADDING_OVERHEAD {
                    return;
                }
                let joined = std::mem::take(&mut self.head);
                return self.unpad(&joined, out);
            }
            if b.len() >= PADDING_OVERHEAD && b[..16] == self.uuid {
                self.remaining_command = 5;
                return self.unpad_body(&b[16..], out);
            }
            out.extend_from_slice(b);
            return;
        }
        self.unpad_body(b, out);
    }

    fn unpad_body(&mut self, mut b: &[u8], out: &mut Vec<u8>) {
        while !b.is_empty() {
            if self.remaining_command > 0 {
                let d = b[0] as i32;
                b = &b[1..];
                match self.remaining_command {
                    5 => self.current_command = d,
                    4 => self.remaining_content = d << 8,
                    3 => self.remaining_content |= d,
                    2 => self.remaining_padding = d << 8,
                    1 => self.remaining_padding |= d,
                    _ => {}
                }
                self.remaining_command -= 1;
            } else if self.remaining_content > 0 {
                let n = (self.remaining_content as usize).min(b.len());
                out.extend_from_slice(&b[..n]);
                b = &b[n..];
                self.remaining_content -= n as i32;
            } else {
                let n = (self.remaining_padding.max(0) as usize).min(b.len());
                b = &b[n..];
                self.remaining_padding -= n as i32;
            }
            if self.remaining_command <= 0
                && self.remaining_content <= 0
                && self.remaining_padding <= 0
            {
                if self.current_command == 0 {
                    self.remaining_command = 5;
                } else {
                    self.remaining_command = -1;
                    self.remaining_content = -1;
                    self.remaining_padding = -1;
                    if !b.is_empty() {
                        out.extend_from_slice(b);
                    }
                    break;
                }
            }
        }
    }

    /// Post-read evaluation from `VisionReader.ReadMultiBuffer`.
    /// Returns `true` when the peer announced direct copy.
    fn settle(&mut self) -> bool {
        if self.remaining_content > 0 || self.remaining_padding > 0 || self.current_command == 0 {
            self.within_padding = true;
            false
        } else if self.current_command == 1 {
            self.within_padding = false;
            false
        } else if self.current_command == 2 {
            self.within_padding = false;
            true
        } else {
            false
        }
    }
}

/// One side of a Vision session: a padding writer, an unpadding reader and
/// the shared traffic classifier. The same type serves both the client
/// (writer = uplink) and a test server (writer = downlink).
#[derive(Debug)]
pub struct Vision {
    pub filter: TrafficFilter,
    pub padder: Padder,
    pub unpadder: Unpadder,
}

impl Vision {
    pub fn new(uuid: [u8; 16]) -> Self {
        Self::with_seed(uuid, PaddingSeed::default())
    }

    pub fn with_seed(uuid: [u8; 16], seed: PaddingSeed) -> Self {
        Self {
            filter: TrafficFilter::default(),
            padder: Padder::new(uuid, seed),
            unpadder: Unpadder::new(uuid),
        }
    }

    /// Xray's "Insert padding with empty content to camouflage VLESS header".
    pub fn encode_camouflage(&mut self, out: &mut Vec<u8>) {
        self.padder.pad(&[], CMD_CONTINUE, true, out);
    }

    /// `VisionWriter.WriteMultiBuffer` for one chunk of plaintext. Returns
    /// `true` when, after `out` has been flushed, the writer must switch to
    /// direct (unencrypted) copy.
    pub fn encode_write(&mut self, data: &[u8], out: &mut Vec<u8>) -> bool {
        if self.filter.packets_to_filter > 0 {
            self.filter.filter(data);
        }
        if !self.padder.is_padding {
            out.extend_from_slice(data);
            return false;
        }
        if data.is_empty() {
            self.encode_camouflage(out);
            return false;
        }

        let is_complete = is_complete_record(data);
        let pieces = reshape(data);
        let last = pieces.len() - 1;
        let mut long_padding = self.filter.is_tls;
        let mut switch_to_direct = false;

        for (i, piece) in pieces.iter().enumerate() {
            if self.filter.is_tls
                && piece.len() >= 6
                && piece[..3] == *TLS_APPLICATION_DATA_START
                && is_complete
            {
                if self.filter.enable_xtls {
                    switch_to_direct = true;
                }
                let mut command = CMD_CONTINUE;
                if i == last {
                    command = if self.filter.enable_xtls {
                        CMD_DIRECT
                    } else {
                        CMD_END
                    };
                }
                self.padder.pad(piece, command, true, out);
                self.padder.is_padding = false;
                long_padding = false;
                continue;
            } else if !self.filter.is_tls12_or_above && self.filter.packets_to_filter <= 1 {
                // Not TLS (or too old): finish padding one packet early, the
                // remaining pieces of this chunk go out as-is.
                self.padder.is_padding = false;
                self.padder.pad(piece, CMD_END, long_padding, out);
                for rest in &pieces[i + 1..] {
                    out.extend_from_slice(rest);
                }
                break;
            }
            let mut command = CMD_CONTINUE;
            if i == last && !self.padder.is_padding {
                command = if self.filter.enable_xtls {
                    CMD_DIRECT
                } else {
                    CMD_END
                };
            }
            self.padder.pad(piece, command, long_padding, out);
        }
        switch_to_direct
    }

    /// `VisionReader.ReadMultiBuffer` for one chunk read from the tunnel.
    /// Returns `true` when the reader must switch to direct copy now.
    pub fn decode_read(&mut self, data: &[u8], out: &mut Vec<u8>) -> bool {
        let mut switch_to_direct = false;
        let start = out.len();
        if self.unpadder.within_padding || self.filter.packets_to_filter > 0 {
            self.unpadder.unpad(data, out);
            switch_to_direct = self.unpadder.settle();
        } else {
            out.extend_from_slice(data);
        }
        if self.filter.packets_to_filter > 0 && out.len() > start {
            let chunk = out[start..].to_vec();
            self.filter.filter(&chunk);
        }
        switch_to_direct
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [0x11; 16];

    fn tls_record(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut r = vec![kind, 0x03, 0x03];
        r.extend_from_slice(&(body.len() as u16).to_be_bytes());
        r.extend_from_slice(body);
        r
    }

    fn client_hello() -> Vec<u8> {
        let mut body = vec![TLS_HANDSHAKE_CLIENT_HELLO, 0, 0, 40];
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xAA; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        let mut r = tls_record(0x16, &body);
        r[2] = 0x01; // legacy record version 3.1 on the first flight
        r
    }

    fn server_hello(cipher: u16, tls13: bool) -> Vec<u8> {
        let mut body = vec![TLS_HANDSHAKE_SERVER_HELLO, 0, 0, 0];
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xBB; 32]);
        body.push(32);
        body.extend_from_slice(&[0xCC; 32]);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0);
        let mut exts = Vec::new();
        if tls13 {
            exts.extend_from_slice(TLS13_SUPPORTED_VERSIONS);
        }
        exts.extend_from_slice(&[0x00, 0x33, 0x00, 0x02, 0x00, 0x1d]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let len = body.len() - 4;
        body[1..4].copy_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        tls_record(0x16, &body)
    }

    #[test]
    fn padding_block_layout_and_round_trip() {
        let mut padder = Padder::new(UUID, PaddingSeed::default());
        let mut out = Vec::new();
        padder.pad(b"hello", CMD_CONTINUE, false, &mut out);
        assert_eq!(&out[..16], &UUID);
        assert_eq!(out[16], CMD_CONTINUE);
        assert_eq!(&out[17..19], &5u16.to_be_bytes());
        let padding = u16::from_be_bytes([out[19], out[20]]) as usize;
        assert!(padding < 256);
        assert_eq!(&out[21..26], b"hello");
        assert_eq!(out.len(), 21 + 5 + padding);

        padder.pad(b"world", CMD_END, false, &mut out);
        assert!(out.len() > 26 + padding + 5 + 5);
        assert_eq!(out[21 + 5 + padding], CMD_END, "second block has no uuid");

        let mut unpadder = Unpadder::new(UUID);
        let mut content = Vec::new();
        unpadder.unpad(&out, &mut content);
        assert_eq!(content, b"helloworld");
        assert!(!unpadder.settle());
        assert!(!unpadder.within_padding);
    }

    #[test]
    fn long_padding_hides_short_content_length() {
        let mut padder = Padder::new(UUID, PaddingSeed::default());
        for _ in 0..50 {
            let mut out = Vec::new();
            padder.pad(b"GET / HTTP/1.1", CMD_CONTINUE, true, &mut out);
            let block_len = out.len() - if out.starts_with(&UUID) { 16 } else { 0 };
            assert!(
                (900..=1400).contains(&(block_len - 5)),
                "got {}",
                block_len - 5
            );
        }
    }

    #[test]
    fn unpadder_handles_blocks_split_across_reads() {
        let mut padder = Padder::new(UUID, PaddingSeed::default());
        let mut wire = Vec::new();
        padder.pad(b"abc", CMD_CONTINUE, true, &mut wire);
        padder.pad(b"defgh", CMD_DIRECT, false, &mut wire);
        wire.extend_from_slice(b"RAW-AFTER-DIRECT");

        let mut unpadder = Unpadder::new(UUID);
        let mut content = Vec::new();
        let mut switched = false;
        for chunk in wire.chunks(7) {
            unpadder.unpad(chunk, &mut content);
            if unpadder.settle() {
                switched = true;
            }
        }
        assert!(switched);
        assert_eq!(content, b"abcdefghRAW-AFTER-DIRECT");
    }

    #[test]
    fn unpadder_passes_through_without_uuid_marker() {
        let mut unpadder = Unpadder::new(UUID);
        let mut out = Vec::new();
        unpadder.unpad(b"plain data without marker", &mut out);
        assert_eq!(out, b"plain data without marker");
    }

    #[test]
    fn filter_detects_tls13_from_server_hello() {
        let mut f = TrafficFilter::default();
        f.filter(&client_hello());
        assert!(f.is_tls);
        assert!(!f.is_tls12_or_above);
        f.filter(&server_hello(0x1302, true));
        assert!(f.is_tls12_or_above);
        assert_eq!(f.cipher, 0x1302);
        assert!(f.enable_xtls);
        assert_eq!(f.packets_to_filter, 0);
    }

    #[test]
    fn filter_keeps_padding_for_tls12_and_ccm8() {
        let mut f = TrafficFilter::default();
        f.filter(&server_hello(0xc02f, false));
        assert!(f.is_tls12_or_above);
        assert!(!f.enable_xtls);
        assert_eq!(f.packets_to_filter, 0);

        let mut f = TrafficFilter::default();
        f.filter(&server_hello(0x1305, true));
        assert!(!f.enable_xtls);
    }

    #[test]
    fn complete_record_detection() {
        let mut data = tls_record(0x17, &[1, 2, 3]);
        data.extend(tls_record(0x17, &[4]));
        assert!(is_complete_record(&data));
        assert!(!is_complete_record(&data[..data.len() - 1]));
        assert!(!is_complete_record(&tls_record(0x16, &[1])));
        assert!(
            is_complete_record(b""),
            "Xray treats an empty buffer as complete"
        );
    }

    #[test]
    fn reshape_keeps_pieces_within_block_limit() {
        let mut data = Vec::new();
        while data.len() < 20_000 {
            data.extend(tls_record(0x17, &[7; 1000]));
        }
        let pieces = reshape(&data);
        assert!(pieces.iter().all(|p| p.len() <= MAX_CONTENT));
        assert_eq!(pieces.iter().map(|p| p.len()).sum::<usize>(), data.len());
        assert_eq!(reshape(&[1, 2, 3]), vec![&[1u8, 2, 3][..]]);
    }

    /// Full client/server exchange for an inner TLS 1.3 connection: both sides
    /// must end up in direct mode and all application bytes must survive.
    #[test]
    fn client_and_server_switch_to_direct_after_tls13_handshake() {
        let mut client = Vision::new(UUID);
        let mut server = Vision::new(UUID);

        let send = |from: &mut Vision, to: &mut Vision, data: &[u8]| -> (Vec<u8>, bool, bool) {
            let mut wire = Vec::new();
            let w_switch = from.encode_write(data, &mut wire);
            let mut plain = Vec::new();
            let r_switch = to.decode_read(&wire, &mut plain);
            (plain, w_switch, r_switch)
        };

        // client -> ClientHello
        let (p, ws, rs) = send(&mut client, &mut server, &client_hello());
        assert_eq!(p, client_hello());
        assert!(!ws && !rs);
        // server -> ServerHello + CCS + encrypted extensions
        let mut flight = server_hello(0x1301, true);
        flight.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        flight.extend(tls_record(0x17, &[9; 100]));
        let (p, ws, rs) = send(&mut server, &mut client, &flight);
        assert_eq!(p, flight);
        assert!(!ws && !rs);
        assert!(client.filter.enable_xtls && server.filter.enable_xtls);
        // client -> CCS + Finished (starts with 0x14: still padded, Continue)
        let mut fin = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        fin.extend(tls_record(0x17, &[8; 50]));
        let (p, ws, rs) = send(&mut client, &mut server, &fin);
        assert_eq!(p, fin);
        assert!(!ws && !rs);
        // client -> first application data: Direct
        let req = tls_record(0x17, b"GET / HTTP/1.1");
        let (p, ws, rs) = send(&mut client, &mut server, &req);
        assert_eq!(p, req);
        assert!(ws, "client writer switches after this flush");
        assert!(rs, "server reader switches now");
        // server -> first application data: Direct
        let resp = tls_record(0x17, b"HTTP/1.1 200 OK");
        let (p, ws, rs) = send(&mut server, &mut client, &resp);
        assert_eq!(p, resp);
        assert!(ws && rs);
    }

    #[test]
    fn non_tls_traffic_ends_padding_without_direct() {
        let mut client = Vision::new(UUID);
        let mut server = Vision::new(UUID);
        let mut ended_at = None;
        for i in 0..9u8 {
            let data = vec![b'a' + i; 100];
            let mut wire = Vec::new();
            let ws = client.encode_write(&data, &mut wire);
            let mut plain = Vec::new();
            let rs = server.decode_read(&wire, &mut plain);
            assert_eq!(plain, data);
            assert!(!ws && !rs);
            match ended_at {
                Some(_) => assert_eq!(wire, data, "after END the data is sent as-is"),
                None if !client.padder.is_padding => {
                    ended_at = Some(i);
                    assert_eq!(
                        wire[0], CMD_END,
                        "the END block carries the last padded chunk"
                    );
                }
                None => assert_ne!(wire, data, "still padded"),
            }
        }
        assert_eq!(
            ended_at,
            Some(6),
            "padding ends one packet before the filter gives up"
        );
        assert!(!client.filter.enable_xtls);
    }
}
