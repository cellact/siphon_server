//! G.711 and Opus, the two audio codecs a peer actually has to bridge.
//!
//! PCMU and PCMA are 8 kHz. Opus is 48 kHz. The bridge speaks PCM between them.

use std::cell::RefCell;
use std::collections::HashMap;

use opus::{Application, Channels, Encoder, Decoder};

thread_local! {
    static OPUS_ENC: RefCell<Option<Encoder>> = const { RefCell::new(None) };
    static OPUS_DEC: RefCell<Option<Decoder>> = const { RefCell::new(None) };
    static OPUS_DEC_8K: RefCell<Option<Decoder>> = const { RefCell::new(None) };
    // One decoder per bridged leg. The bridge decoder stays on the forwarded audio.
    static REC_OPUS: RefCell<HashMap<String, Decoder>> = RefCell::new(HashMap::new());
}

pub fn silence(codec: &str) -> Vec<u8> {
    match codec {
        "pcmu" => vec![0xff; 160],
        "pcma" => vec![0xd5; 160],
        _ => opus_silence(),
    }
}

pub fn opus_silence() -> Vec<u8> {
    let pcm = [0i16; 960];
    encode_opus(&pcm).unwrap_or_else(|_| vec![0xf8, 0xff, 0xfe])
}

/// 8 kHz mono s16 for the tape. `leg` keeps an Opus decoder off the bridge's.
pub fn pcm8_for(leg: &str, codec: &str, payload: &[u8]) -> Vec<i16> {
    if codec.starts_with("opus") {
        return decode_opus_leg(leg, payload);
    }
    if codec.starts_with("pcmu") {
        payload.iter().copied().map(pcmu_decode).collect()
    } else if codec.starts_with("pcma") {
        payload.iter().copied().map(pcma_decode).collect()
    } else {
        Vec::new()
    }
}

pub fn drop_rec_decoder(leg: &str) {
    REC_OPUS.with(|cell| {
        cell.borrow_mut().remove(leg);
    });
}

fn decode_opus_leg(leg: &str, payload: &[u8]) -> Vec<i16> {
    REC_OPUS.with(|cell| {
        let mut map = cell.borrow_mut();
        if !map.contains_key(leg) {
            let Ok(dec) = Decoder::new(8_000, Channels::Mono) else {
                return Vec::new();
            };
            map.insert(leg.to_string(), dec);
        }
        let Some(dec) = map.get_mut(leg) else {
            return Vec::new();
        };
        let mut pcm = vec![0i16; 960];
        match dec.decode(payload, &mut pcm, false) {
            Ok(n) => {
                pcm.truncate(n);
                pcm
            }
            Err(_) => Vec::new(),
        }
    })
}

/// RFC 4733 event code. OpenAI's `a=fmtp` is `0-15`, which is these.
pub fn dtmf_event_code(digit: char) -> Option<u8> {
    match digit {
        '0'..='9' => Some((digit as u8) - b'0'),
        '*' => Some(10),
        '#' => Some(11),
        'A'..='D' => Some(12 + (digit as u8 - b'A')),
        'a'..='d' => Some(12 + (digit as u8 - b'a')),
        _ => None,
    }
}

/// One RFC 4733 telephone-event packet. `duration` is in timestamp units
/// (160 per 20 ms at 8 kHz). The end bit is set on the final retransmits.
pub fn dtmf_event(event: u8, end: bool, volume: u8, duration: u16) -> [u8; 4] {
    let vr = (volume & 0x3f) | if end { 0x80 } else { 0 };
    [
        event,
        vr,
        (duration >> 8) as u8,
        (duration & 0xff) as u8,
    ]
}

/// One 20 ms G.711 frame of a DTMF tone. `frame` is the frame index so the
/// phase continues across the burst. A carrier that ignores telephone-event
/// hears this. OpenAI does not.
pub fn dtmf_frame(codec: &str, digit: char, frame: u32) -> Result<Vec<u8>, String> {
    let (low, high) = dtmf_hz(digit).ok_or_else(|| format!("not a dtmf digit: {digit}"))?;
    let mut pcm = [0i16; 160];
    for (n, sample) in pcm.iter_mut().enumerate() {
        let t = (frame as f32 * 160.0 + n as f32) / 8000.0;
        let tone = (low * t).sin() * 0.45 + (high * t).sin() * 0.35;
        *sample = (tone * 32767.0) as i16;
    }
    Ok(match codec {
        "pcmu" => pcm.into_iter().map(pcmu_encode).collect(),
        "pcma" => pcm.into_iter().map(pcma_encode).collect(),
        other => return Err(format!("dtmf needs pcmu or pcma, got {other}")),
    })
}

fn dtmf_hz(digit: char) -> Option<(f32, f32)> {
    const TWO_PI: f32 = std::f32::consts::TAU;
    let (low, high) = match digit {
        '1' => (697.0, 1209.0),
        '2' => (697.0, 1336.0),
        '3' => (697.0, 1477.0),
        '4' => (770.0, 1209.0),
        '5' => (770.0, 1336.0),
        '6' => (770.0, 1477.0),
        '7' => (852.0, 1209.0),
        '8' => (852.0, 1336.0),
        '9' => (852.0, 1477.0),
        '*' => (941.0, 1209.0),
        '0' => (941.0, 1336.0),
        '#' => (941.0, 1477.0),
        'A' => (697.0, 1633.0),
        'B' => (770.0, 1633.0),
        'C' => (852.0, 1633.0),
        'D' => (941.0, 1633.0),
        _ => return None,
    };
    Some((low * TWO_PI, high * TWO_PI))
}

pub fn transcode(in_codec: &str, payload: &[u8], out_codec: &str) -> Vec<u8> {
    if in_codec == out_codec {
        return payload.to_vec();
    }
    // libopus resamples to 8 kHz. Point-sampling 48 kHz down to 8 kHz aliases.
    if in_codec == "opus" && (out_codec == "pcmu" || out_codec == "pcma") {
        let pcm8 = match decode_opus_8k(payload) {
            Ok(pcm) => pcm,
            Err(_) => return Vec::new(),
        };
        return match out_codec {
            "pcmu" => pcm8.into_iter().map(pcmu_encode).collect(),
            _ => pcm8.into_iter().map(pcma_encode).collect(),
        };
    }
    let pcm48 = match decode(in_codec, payload) {
        Some(pcm) => pcm,
        None => return Vec::new(),
    };
    encode(out_codec, &pcm48).unwrap_or_default()
}

fn decode(codec: &str, payload: &[u8]) -> Option<Vec<i16>> {
    match codec {
        "pcmu" => Some(upsample(&payload.iter().copied().map(pcmu_decode).collect::<Vec<_>>())),
        "pcma" => Some(upsample(&payload.iter().copied().map(pcma_decode).collect::<Vec<_>>())),
        "opus" => decode_opus(payload).ok(),
        _ => None,
    }
}

fn encode(codec: &str, pcm48: &[i16]) -> Result<Vec<u8>, String> {
    match codec {
        "pcmu" => Ok(downsample(pcm48).into_iter().map(pcmu_encode).collect()),
        "pcma" => Ok(downsample(pcm48).into_iter().map(pcma_encode).collect()),
        "opus" => encode_opus(pcm48),
        other => Err(format!("no codec {other}")),
    }
}

fn encode_opus(pcm48: &[i16]) -> Result<Vec<u8>, String> {
    OPUS_ENC.with(|cell| {
        let mut borrow = cell.borrow_mut();
        if borrow.is_none() {
            *borrow = Some(
                Encoder::new(48_000, Channels::Mono, Application::Voip)
                    .map_err(|err| err.to_string())?,
            );
        }
        let enc = borrow.as_mut().unwrap();
        let mut frame = [0i16; 960];
        let n = pcm48.len().min(960);
        frame[..n].copy_from_slice(&pcm48[..n]);
        let mut out = vec![0u8; 4000];
        let written = enc.encode(&frame, &mut out).map_err(|err| err.to_string())?;
        out.truncate(written);
        Ok(out)
    })
}

fn decode_opus(payload: &[u8]) -> Result<Vec<i16>, String> {
    decode_opus_at(&OPUS_DEC, 48_000, 960, payload)
}

fn decode_opus_8k(payload: &[u8]) -> Result<Vec<i16>, String> {
    decode_opus_at(&OPUS_DEC_8K, 8_000, 160 * 6, payload)
}

fn decode_opus_at(
    slot: &'static std::thread::LocalKey<RefCell<Option<Decoder>>>,
    rate: u32,
    cap: usize,
    payload: &[u8],
) -> Result<Vec<i16>, String> {
    slot.with(|cell| {
        let mut borrow = cell.borrow_mut();
        if borrow.is_none() {
            *borrow = Some(Decoder::new(rate, Channels::Mono).map_err(|err| err.to_string())?);
        }
        let dec = borrow.as_mut().unwrap();
        let mut pcm = vec![0i16; cap];
        let n = dec.decode(payload, &mut pcm, false).map_err(|err| err.to_string())?;
        pcm.truncate(n);
        Ok(pcm)
    })
}

fn upsample(pcm8: &[i16]) -> Vec<i16> {
    if pcm8.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(pcm8.len() * 6);
    for (index, sample) in pcm8.iter().enumerate() {
        let next = pcm8.get(index + 1).copied().unwrap_or(*sample);
        for step in 0..6 {
            let sample = *sample as i32;
            let delta = (next as i32 - sample) * step / 6;
            out.push((sample + delta) as i16);
        }
    }
    out
}

fn downsample(pcm48: &[i16]) -> Vec<i16> {
    pcm48.chunks(6).map(|chunk| chunk[0]).collect()
}

fn pcmu_decode(byte: u8) -> i16 {
    let byte = !byte;
    let sign = byte & 0x80;
    let exp = (byte >> 4) & 0x07;
    let mant = byte & 0x0f;
    let mut sample = (((mant as i32) << 3) + 0x84) << exp;
    sample -= 0x84;
    if sign != 0 { -sample as i16 } else { sample as i16 }
}

fn pcmu_encode(sample: i16) -> u8 {
    let mut sample = sample as i32;
    let sign = if sample < 0 { 0x80 } else { 0 };
    if sample < 0 {
        sample = -sample;
    }
    sample += 0x84;
    if sample > 0x7fff {
        sample = 0x7fff;
    }
    let mut exp = 7;
    let mut mask = 0x4000;
    while exp > 0 && (sample & mask) == 0 {
        exp -= 1;
        mask >>= 1;
    }
    let mant = (sample >> (exp + 3)) & 0x0f;
    !(sign | (exp << 4) | mant as u8)
}

fn pcma_decode(byte: u8) -> i16 {
    let byte = byte ^ 0x55;
    let sign = byte & 0x80;
    let exp = (byte >> 4) & 0x07;
    let mant = byte & 0x0f;
    let mut sample = ((mant as i32) << 4) + 8;
    if exp != 0 {
        sample = (sample + 0x100) << (exp - 1);
    }
    if sign != 0 { -sample as i16 } else { sample as i16 }
}

fn pcma_encode(sample: i16) -> u8 {
    let mut sample = sample as i32;
    let sign = if sample < 0 { 0x80 } else { 0 };
    if sample < 0 {
        sample = -sample;
    }
    if sample > 0x7fff {
        sample = 0x7fff;
    }
    let mut exp = 7;
    let mut mask = 0x4000;
    while exp > 0 && (sample & mask) == 0 {
        exp -= 1;
        mask >>= 1;
    }
    let mant = if exp == 0 { (sample >> 4) & 0x0f } else { (sample >> (exp + 3)) & 0x0f };
    (sign | (exp << 4) | mant as u8) ^ 0x55
}
