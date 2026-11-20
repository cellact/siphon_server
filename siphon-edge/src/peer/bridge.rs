//! PCM copy between two peers. Each peer keeps its own payload type.
//! Telephone-event is not audio: the end packet of a digit is reported up.
//!
//! A same-session bridge also keeps an 8 kHz stereo tape. `unbridge` turns
//! that into the wav `bridge.stop` already knows how to upload.

use std::time::{SystemTime, UNIX_EPOCH};

use super::codec;

const MAX_SAMPLES: usize = 8_000 * 60 * 30;

#[derive(Default)]
pub struct RecOut {
    pub wav_b64: String,
    pub started_ms: u64,
    pub ended_ms: u64,
}

pub struct Tape {
    left_key: String,
    right_key: String,
    left: Vec<i16>,
    right: Vec<i16>,
    started_ms: u64,
}

impl Tape {
    pub fn new(left_key: String, right_key: String) -> Self {
        Self {
            left_key,
            right_key,
            left: Vec::new(),
            right: Vec::new(),
            started_ms: now_ms(),
        }
    }

    pub fn retarget(&mut self, left_key: String, right_key: String) {
        if self.left_key != left_key {
            codec::drop_rec_decoder(&self.left_key);
            self.left_key = left_key;
        }
        if self.right_key != right_key {
            codec::drop_rec_decoder(&self.right_key);
            self.right_key = right_key;
        }
    }

    pub fn push_payload(&mut self, from: &str, codec_name: &str, payload: &[u8]) {
        if payload.is_empty() || (from != self.left_key && from != self.right_key) {
            return;
        }
        let pcm = codec::pcm8_for(from, codec_name, payload);
        if pcm.is_empty() {
            return;
        }
        let buf = if from == self.left_key { &mut self.left } else { &mut self.right };
        let room = MAX_SAMPLES.saturating_sub(buf.len());
        if room == 0 {
            return;
        }
        buf.extend(pcm.into_iter().take(room));
    }

    pub fn discard(self) {
        codec::drop_rec_decoder(&self.left_key);
        codec::drop_rec_decoder(&self.right_key);
    }

    pub fn finish(self) -> RecOut {
        codec::drop_rec_decoder(&self.left_key);
        codec::drop_rec_decoder(&self.right_key);
        let wav = stereo_wav(&self.left, &self.right);
        RecOut {
            wav_b64: if wav.is_empty() { String::new() } else { b64(&wav) },
            started_ms: self.started_ms,
            ended_ms: now_ms(),
        }
    }
}

/// Left is the WebRTC client. Right is rtpengine (`pc2`, or inbound `pc1`).
pub fn sides(a: &str, b: &str) -> (String, String) {
    let a_leg = peer_leg(a);
    let b_leg = peer_leg(b);
    if a_leg == "pc2" {
        return (b.to_string(), a.to_string());
    }
    if b_leg == "pc2" {
        return (a.to_string(), b.to_string());
    }
    if a_leg.starts_with("callee:") && b_leg == "pc1" {
        return (a.to_string(), b.to_string());
    }
    (a.to_string(), b.to_string())
}

fn peer_leg(id: &str) -> &str {
    id.split_once('\n').map(|(_, leg)| leg).unwrap_or(id)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Same layout as `CallRecorder.wav_bytes`: 8 kHz s16le stereo.
/// Empty until one side has 20 ms (160 samples).
fn stereo_wav(left: &[i16], right: &[i16]) -> Vec<u8> {
    if left.len() < 160 && right.len() < 160 {
        return Vec::new();
    }
    let n = left.len().max(right.len());
    let mut data = Vec::with_capacity(n * 4);
    for i in 0..n {
        let l = left.get(i).copied().unwrap_or(0);
        let r = right.get(i).copied().unwrap_or(0);
        data.extend_from_slice(&l.to_le_bytes());
        data.extend_from_slice(&r.to_le_bytes());
    }
    let mut out = Vec::with_capacity(44 + data.len());
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&((36 + data.len()) as u32).to_le_bytes());
    out.extend_from_slice(b"WAVE");
    out.extend_from_slice(b"fmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&8000u32.to_le_bytes());
    out.extend_from_slice(&32000u32.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend(data);
    out
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(T[((n >> 6) & 63) as usize] as char);
        out.push(T[(n & 63) as usize] as char);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let n = (data[i] as u32) << 16;
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push(T[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

#[derive(Debug)]
pub struct Bridge {
    pub a: String,
    pub b: String,
    pub a_to_b: u64,
    pub b_to_a: u64,
}

impl Bridge {
    pub fn other(&self, id: &str) -> Option<&str> {
        if id == self.a {
            Some(&self.b)
        } else if id == self.b {
            Some(&self.a)
        } else {
            None
        }
    }

    pub fn count(&mut self, from: &str) {
        if from == self.a {
            self.a_to_b += 1;
        } else if from == self.b {
            self.b_to_a += 1;
        }
    }
}

pub fn forward(in_codec: &str, payload: &[u8], out_codec: &str) -> Vec<u8> {
    codec::transcode(in_codec, payload, out_codec)
}

/// RFC 4733. Only the packet with the end bit set is a digit, so a
/// repeating event does not surface once per frame.
pub fn dtmf_end(payload: &[u8]) -> Option<char> {
    if payload.len() < 2 || payload[1] & 0x80 == 0 {
        return None;
    }
    Some(match payload[0] {
        0..=9 => (b'0' + payload[0]) as char,
        10 => '*',
        11 => '#',
        12..=15 => (b'A' + (payload[0] - 12)) as char,
        _ => return None,
    })
}
