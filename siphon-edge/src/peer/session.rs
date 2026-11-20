//! One peer. One [`Rtc`](str0m::Rtc), so a later offer that adds audio stays
//! on the ICE agent and the DTLS association that are already up.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::ChannelId;
use str0m::format::{Codec, FormatParams};
use str0m::media::{Direction, Frequency, MediaKind, MediaTime, Mid, Pt};
use str0m::net::{Protocol, Receive};
use str0m::rtp::Ssrc;
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};

#[derive(Debug, Clone)]
pub struct Packet {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub contents: Vec<u8>,
}

#[derive(Debug)]
pub enum ScriptEvent {
    ChannelOpen,
    ChannelClose,
    ChannelData(String),
    Connection(String),
    Ice(String),
    Dtls(String),
    Dtmf(char),
    Audio { codec: String, payload: Vec<u8> },
}

pub struct Drain {
    pub transmits: Vec<Packet>,
    pub events: Vec<ScriptEvent>,
}

enum QueuedDtmf {
    Inband(Vec<u8>),
    Event { pt: u8, ts: u32, body: [u8; 4] },
}

pub struct Peer {
    rtc: Rtc,
    now: Instant,
    pending: Option<SdpPendingOffer>,
    answer: Option<String>,
    local_sdp: String,
    channel: Option<ChannelId>,
    audio_mid: Option<Mid>,
    send_pt: Option<Pt>,
    pub send_codec: String,
    /// Payload type to codec, from the remote SDP. Incoming RTP is labeled
    /// from this, not from `send_codec`. Opus PT 111 was falling through to
    /// PCMU and the bridge decoded it as μ-law.
    rx_codecs: Vec<(u8, String)>,
    te_pts: Vec<u8>,
    pub candidates: Vec<String>,
    pub connected: bool,
    pub ice: String,
    pub dtls: String,
    ts: u32,
    /// DTMF waiting to go out, one packet every 20 ms. Dumping them in one
    /// shot plays the tone at 4x and the far side does not detect it.
    dtmf_q: VecDeque<QueuedDtmf>,
    dtmf_next: Instant,
    /// RTP timestamp to resume voice at after an RFC 4733 event. The event
    /// itself keeps one timestamp and reports the length in the duration field.
    dtmf_resume_ts: Option<u32>,
    /// While this is in the future, pc2 must not send voice over the tone.
    suppress_audio_until: Instant,
    pub want_audio: bool,
    next_dir: Option<Direction>,
    pub host: SocketAddr,
    relay: Option<SocketAddr>,
    remote_candidates: u32,
    /// Offer arrived with no remote candidate. str0m's handshake timer runs
    /// off `now`, and `advance` moves `now` in real time. Holding it until the
    /// first candidate keeps that budget for the trickle, instead of spending
    /// it while the agent has nothing to check.
    hold_clock: bool,
}

impl Peer {
    pub fn new(host: SocketAddr, want_audio: bool) -> Result<Self, String> {
        let now = Instant::now();
        // Opus stays on (str0m's default). PCMU/PCMA are what the phone's RING
        // offer carries after the G.711 narrow. Without them accept_offer
        // rejects the audio m-line: port 0, missing from BUNDLE.
        let mut config = Rtc::builder().enable_pcmu(true, false).enable_pcma(true, false);
        {
            let codecs = config.codec_config();
            // iOS offers 126 telephone-event/8000 and 110 telephone-event/48000.
            for (pt, clock) in [
                (126u8, Frequency::EIGHT_KHZ),
                (110, Frequency::FORTY_EIGHT_KHZ),
            ] {
                codecs.add_config(
                    Pt::from(pt),
                    None,
                    Codec::Tele,
                    clock,
                    None,
                    FormatParams {
                        telephone_event_max: Some(16),
                        ..FormatParams::default()
                    },
                );
            }
        }
        let mut rtc = config.build(now);
        let candidate = Candidate::host(host, "udp").map_err(|err| err.to_string())?;
        let line = candidate.to_sdp_string();
        rtc.add_local_candidate(candidate);
        Ok(Self {
            rtc,
            now,
            pending: None,
            answer: None,
            local_sdp: String::new(),
            channel: None,
            audio_mid: None,
            send_pt: None,
            send_codec: String::new(),
            rx_codecs: Vec::new(),
            te_pts: Vec::new(),
            candidates: vec![line],
            connected: false,
            ice: "new".into(),
            dtls: "new".into(),
            ts: 0,
            dtmf_q: VecDeque::new(),
            dtmf_next: now,
            dtmf_resume_ts: None,
            suppress_audio_until: now,
            want_audio,
            next_dir: None,
            host,
            relay: None,
            remote_candidates: 0,
            hold_clock: false,
        })
    }

    pub fn ufrag(&mut self) -> String {
        self.rtc.direct_api().local_ice_credentials().ufrag
    }

    pub fn add_host_like(&mut self, candidate: Candidate) {
        let line = candidate.to_sdp_string();
        if candidate.kind() == str0m::CandidateKind::Relayed {
            self.relay = Some(candidate.addr());
        }
        if self.rtc.add_local_candidate(candidate).is_some() && !self.candidates.contains(&line) {
            self.candidates.push(line);
        }
    }

    pub fn relay(&self) -> Option<SocketAddr> {
        self.relay
    }

    pub fn create_offer(&mut self) -> Result<String, String> {
        self.create_offer_with(false)
    }

    /// Next offer marks the existing audio m-line inactive. Staging softEnd
    /// nulls the track so createOffer is a new offer with a pending answer.
    pub fn arm_inactive_audio(&mut self) {
        self.next_dir = Some(Direction::Inactive);
    }

    pub fn create_offer_with(&mut self, with_audio: bool) -> Result<String, String> {
        if with_audio {
            self.want_audio = true;
        }
        let mut change = self.rtc.sdp_api();
        if self.channel.is_none() {
            self.channel = Some(change.add_channel("chat".to_string()));
        }
        // Do not store the mid until apply() actually emits it. Setting it
        // early and then returning the previous DC-only SDP is how RING went
        // out at 589 bytes and the phone auto-answered.
        let added_audio = if self.want_audio && self.audio_mid.is_none() {
            Some(change.add_media(
                MediaKind::Audio,
                Direction::SendRecv,
                None,
                None,
                None,
            ))
        } else {
            None
        };
        if let Some(mid) = self.audio_mid {
            if with_audio {
                change.set_direction(mid, Direction::SendRecv);
            } else if self.next_dir == Some(Direction::Inactive) {
                change.set_direction(mid, Direction::Inactive);
            }
        }
        self.next_dir = None;
        // Re-offer on an existing m-line. Direction back to sendrecv is the
        // call. The ICE agent and the DTLS session stay. A new ufrag is an
        // ICE restart, and the phone treats that as the peer connection dying.
        match change.apply() {
            Some((offer, pending)) => {
                if let Some(mid) = added_audio {
                    self.audio_mid = Some(mid);
                }
                self.pending = Some(pending);
                let sdp = offer.to_sdp_string();
                self.note_sdp(&sdp);
                self.local_sdp = sdp.clone();
                if with_audio && !sdp.contains("m=audio") {
                    return Err("offer did not add m=audio".into());
                }
                if with_audio && audio_section_inactive(&sdp) {
                    return Err("offer audio is inactive".into());
                }
                Ok(sdp)
            }
            None => {
                if with_audio || added_audio.is_some() {
                    return Err("offer did not add m=audio".into());
                }
                if self.local_sdp.is_empty() {
                    Err("offer had nothing to add".into())
                } else {
                    Ok(self.local_sdp.clone())
                }
            }
        }
    }

    pub fn set_remote(&mut self, kind: &str, sdp: &str) -> Result<(), String> {
        self.set_remote_ex(kind, sdp, false)
    }

    /// `refresh_audio` is the caller's choice. On a sendrecv re-offer it
    /// mints one new SSRC before `accept_offer`, so the answer is not the
    /// previous one. Off by default. An inactive offer is never refreshed.
    pub fn set_remote_ex(&mut self, kind: &str, sdp: &str, refresh_audio: bool) -> Result<(), String> {
        self.note_sdp(sdp);
        if kind == "offer" {
            self.pending = None;
            if refresh_audio && offer_sends_audio(sdp) {
                self.refresh_audio_sender();
            }
            let offer = SdpOffer::from_sdp_string(sdp).map_err(|err| err.to_string())?;
            let answer = self.rtc.sdp_api().accept_offer(offer).map_err(|err| err.to_string())?;
            let text = answer.to_sdp_string();
            self.note_sdp(&text);
            self.local_sdp = text.clone();
            self.answer = Some(text);
            let offered_candidate = sdp.to_ascii_lowercase().contains("a=candidate:");
            self.hold_clock = self.remote_candidates == 0 && !offered_candidate;
            Ok(())
        } else {
            let answer = SdpAnswer::from_sdp_string(sdp).map_err(|err| err.to_string())?;
            let pending = self.pending.take().ok_or("no pending offer for this answer")?;
            self.rtc.sdp_api().accept_answer(pending, answer).map_err(|err| err.to_string())?;
            Ok(())
        }
    }

    pub fn take_answer(&self) -> Option<String> {
        self.answer.clone()
    }

    pub fn add_remote_candidate(&mut self, line: &str) -> Result<(), String> {
        let line = line.trim().trim_start_matches("a=").trim();
        if line.is_empty() || line.eq_ignore_ascii_case("end-of-candidates") {
            return Ok(());
        }
        let candidate = Candidate::from_sdp_string(line).map_err(|err| err.to_string())?;
        self.rtc.add_remote_candidate(candidate);
        self.remote_candidates = self.remote_candidates.saturating_add(1);
        self.hold_clock = false;
        Ok(())
    }

    pub fn hold_clock(&self) -> bool {
        self.hold_clock
    }

    /// New transmit SSRC on an audio stream that already exists. No RTX:
    /// a second `a=ssrc` makes Android reject the SDP. Direction is left to
    /// `accept_offer`, which inverts the remote sendrecv back onto this mid.
    fn refresh_audio_sender(&mut self) {
        let Some(mid) = self.audio_mid else {
            return;
        };
        let mut api = self.rtc.direct_api();
        if api.stream_tx_by_mid(mid, None).is_none() {
            return;
        }
        let ssrc = api.new_ssrc();
        let _ = api.reset_stream_tx(mid, None, ssrc, None);
    }

    pub fn rotate_ssrc(&mut self) -> Result<(), String> {
        // Callee PC is DC-only until RING. Arm audio so the next offer adds
        // m=audio. Without that the "ring" is another datachannel offer, the
        // phone auto-answers it, and the caller stays on the ringing screen.
        if self.audio_mid.is_none() {
            self.want_audio = true;
            return Ok(());
        }
        let mid = self.audio_mid.ok_or("no audio mid")?;
        let (ssrc, rtx) = {
            let api = self.rtc.direct_api();
            (api.new_ssrc(), api.new_ssrc())
        };
        if self.rtc.direct_api().reset_stream_tx(mid, None, ssrc, Some(rtx)).is_none() {
            return Err("ssrc reset found no audio stream".into());
        }
        Ok(())
    }

    pub fn tx_ssrc_label(&mut self) -> Option<String> {
        let mid = self.audio_mid?;
        let mut api = self.rtc.direct_api();
        let tx = api.stream_tx_by_mid(mid, None)?;
        Some(format!("{:?}", tx.ssrc()))
    }

    pub fn send_text(&mut self, text: &str) -> Result<(), String> {
        let id = self.channel.ok_or("no data channel")?;
        let mut channel = self.rtc.channel(id).ok_or("data channel is not open")?;
        channel.write(false, text.as_bytes()).map_err(|err| err.to_string())?;
        Ok(())
    }

    pub fn write_audio(&mut self, payload: &[u8]) -> Result<(), String> {
        let mid = self.audio_mid.ok_or("no audio mid")?;
        let pt = self.send_pt.ok_or("no send payload type")?;
        let writer = self.rtc.writer(mid).ok_or("audio is not sending")?;
        let (clock, mut step) = send_clock(&self.send_codec);
        if matches!(self.send_codec.as_str(), "pcmu" | "pcma") && !payload.is_empty() {
            step = payload.len() as u32;
        }
        let time = MediaTime::new(self.ts as u64, clock);
        if self.now < self.suppress_audio_until || !self.dtmf_q.is_empty() {
            // The tone owns `ts` until the queue is empty. Advancing here
            // puts the next voice packet in the middle of the tone.
            return Ok(());
        }
        writer.write(pt, self.now, time, payload).map_err(|err| err.to_string())?;
        self.ts = self.ts.wrapping_add(step);
        Ok(())
    }

    pub fn inject_dtmf(&mut self, digit: char, rfc4733: bool) -> Result<(), String> {
        let _ = self.audio_mid.ok_or("no audio mid")?;
        let _ = self.send_pt.ok_or("no send payload type")?;
        // 240 ms. One packet per 20 ms. A single burst leaves the socket in
        // ~60 ms and the far side does not detect a digit.
        let frames = 12u32;
        let mut queued = VecDeque::with_capacity(frames as usize);
        self.dtmf_resume_ts = None;
        if rfc4733 {
            let pt = *self.te_pts.first().ok_or("no telephone-event payload type")?;
            let event = super::codec::dtmf_event_code(digit).ok_or_else(|| format!("not a dtmf digit: {digit}"))?;
            let start = self.ts;
            let samples = 160u16 * frames as u16;
            for frame in 0..frames {
                let end = frame >= 9;
                let duration = if end { samples } else { 160 * (frame as u16 + 1) };
                queued.push_back(QueuedDtmf::Event {
                    pt,
                    ts: start,
                    body: super::codec::dtmf_event(event, end, 10, duration),
                });
            }
            self.dtmf_resume_ts = Some(start.wrapping_add(u32::from(samples)));
        } else {
            for frame in 0..frames {
                queued.push_back(QueuedDtmf::Inband(super::codec::dtmf_frame(
                    &self.send_codec,
                    digit,
                    frame,
                )?));
            }
        }
        self.dtmf_q = queued;
        self.dtmf_next = self.now;
        self.suppress_audio_until = self.now + Duration::from_millis(280);
        Ok(())
    }

    fn pump_dtmf(&mut self) -> Result<(), String> {
        let Some(mid) = self.audio_mid else {
            return Ok(());
        };
        let Some(voice_pt) = self.send_pt else {
            return Ok(());
        };
        let (voice_clock, _) = send_clock(&self.send_codec);
        while self.now >= self.dtmf_next {
            let Some(payload) = self.dtmf_q.pop_front() else {
                return Ok(());
            };
            let (pt, ts, clock, bytes, inband_len) = match payload {
                QueuedDtmf::Inband(frame) => {
                    let n = frame.len() as u32;
                    (voice_pt, self.ts, voice_clock, frame, Some(n))
                }
                QueuedDtmf::Event { pt, ts, body } => (
                    Pt::from(pt),
                    ts,
                    Frequency::EIGHT_KHZ,
                    body.to_vec(),
                    None,
                ),
            };
            self.rtc
                .writer(mid)
                .ok_or("audio is not sending")?
                .write(pt, self.now, MediaTime::new(ts as u64, clock), bytes.as_slice())
                .map_err(|err| err.to_string())?;
            if let Some(n) = inband_len {
                self.ts = self.ts.wrapping_add(n);
            } else if self.dtmf_q.is_empty() {
                if let Some(resume) = self.dtmf_resume_ts.take() {
                    self.ts = resume;
                }
            }
            self.dtmf_next += Duration::from_millis(20);
        }
        Ok(())
    }

    pub fn receive(&mut self, source: SocketAddr, destination: SocketAddr, contents: &[u8]) -> Result<(), String> {
        if let Some(mid) = self.audio_mid {
            if contents.len() >= 12
                && (contents[0] & 0xc0) == 0x80
                && !(64..96).contains(&(contents[1] & 0x7f))
            {
                let ssrc = Ssrc::from(u32::from_be_bytes([
                    contents[8],
                    contents[9],
                    contents[10],
                    contents[11],
                ]));
                // expect_stream_rx panics if this mid is not in the session yet.
                // That is the offer-created audio mid before the answer is
                // accepted. A panic kills the peer thread for every call.
                if self.rtc.media(mid).is_some() {
                    let mut api = self.rtc.direct_api();
                    if api.stream_rx(&ssrc).is_none() {
                        api.expect_stream_rx(ssrc, None, mid, None);
                    }
                }
            }
        }
        let contents = contents.try_into().map_err(|_| "datagram too large".to_string())?;
        self.rtc.handle_input(Input::Receive(
            self.now,
            Receive { proto: Protocol::Udp, source, destination, contents },
        )).map_err(|err| err.to_string())
    }

    pub fn advance(&mut self, by: Duration) -> Result<(), String> {
        if self.hold_clock {
            return Ok(());
        }
        self.now += by;
        self.pump_dtmf()?;
        self.rtc.handle_input(Input::Timeout(self.now)).map_err(|err| err.to_string())
    }

    pub fn close(&mut self) {
        self.rtc.disconnect();
        self.connected = false;
        self.ice = "closed".into();
        self.dtls = "closed".into();
    }

    pub fn drain(&mut self) -> Result<Drain, String> {
        let mut transmits = Vec::new();
        let mut events = Vec::new();
        loop {
            match self.rtc.poll_output().map_err(|err| err.to_string())? {
                Output::Timeout(_) => break,
                Output::Transmit(packet) => transmits.push(Packet {
                    source: packet.source,
                    destination: packet.destination,
                    contents: packet.contents.to_vec(),
                }),
                Output::Event(event) => {
                    if let Some(script) = self.on_event(event) {
                        events.push(script);
                    }
                }
            }
        }
        Ok(Drain { transmits, events })
    }

    fn on_event(&mut self, event: Event) -> Option<ScriptEvent> {
        match event {
            Event::Connected => {
                self.connected = true;
                self.dtls = "connected".into();
                Some(ScriptEvent::Dtls("connected".into()))
            }
            Event::IceConnectionStateChange(state) => {
                self.ice = ice_name(state).into();
                Some(ScriptEvent::Ice(self.ice.clone()))
            }
            Event::ChannelOpen(id, _label) => {
                self.channel = Some(id);
                Some(ScriptEvent::ChannelOpen)
            }
            Event::ChannelClose(_) => {
                self.channel = None;
                Some(ScriptEvent::ChannelClose)
            }
            Event::ChannelData(data) => {
                let text = String::from_utf8_lossy(&data.data).into_owned();
                Some(ScriptEvent::ChannelData(text))
            }
            Event::MediaAdded(added) => {
                if added.kind == MediaKind::Audio {
                    self.audio_mid = Some(added.mid);
                }
                None
            }
            Event::MediaData(media) => {
                let pt = *media.pt;
                if self.te_pts.contains(&pt) {
                    return super::bridge::dtmf_end(&media.data).map(ScriptEvent::Dtmf);
                }
                Some(ScriptEvent::Audio {
                    codec: codec_name(pt, &self.rx_codecs, &self.send_codec),
                    payload: media.data.as_ref().to_vec(),
                })
            }
            _ => None,
        }
    }

    fn note_sdp(&mut self, sdp: &str) {
        let mut rtpmap: Vec<(u8, String)> = Vec::new();
        let mut audio_pts: Vec<u8> = Vec::new();
        let mut in_audio = false;
        for line in sdp.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("m=") {
                in_audio = rest.starts_with("audio ");
                if in_audio {
                    audio_pts = rest.split_whitespace().skip(3).filter_map(|pt| pt.parse().ok()).collect();
                }
                continue;
            }
            let Some(rest) = line.strip_prefix("a=rtpmap:") else { continue };
            let mut parts = rest.split_whitespace();
            let Ok(pt) = parts.next().unwrap_or("").parse::<u8>() else { continue };
            let codec = parts.next().unwrap_or("").to_ascii_lowercase();
            if !codec.is_empty() {
                rtpmap.push((pt, codec));
            }
        }
        if audio_pts.is_empty() {
            return;
        }
        self.te_pts.clear();
        self.rx_codecs.clear();
        for (pt, codec) in &rtpmap {
            if codec.starts_with("telephone-event/8000") {
                self.te_pts.push(*pt);
                continue;
            }
            if codec.starts_with("telephone-event/") {
                continue;
            }
            if let Some(name) = codec_key(codec) {
                self.rx_codecs.push((*pt, name.to_string()));
            }
        }
        // What we send is still PCMU when the SDP has it (rank). What we
        // receive is whatever PT is actually on the packet.
        let mut best: Option<(u8, String, u8)> = None;
        for (pt, name) in &self.rx_codecs {
            if !audio_pts.contains(pt) {
                continue;
            }
            let rank = match name.as_str() {
                "pcmu" => 3,
                "pcma" => 2,
                "opus" => 1,
                _ => 0,
            };
            if best.as_ref().map(|(_, _, have)| rank > *have).unwrap_or(true) {
                best = Some((*pt, name.clone(), rank));
            }
        }
        if let Some((pt, name, _)) = best {
            self.send_pt = Some(Pt::from(pt));
            self.send_codec = name;
        }
    }
}

fn send_clock(codec: &str) -> (Frequency, u32) {
    match codec {
        "pcmu" | "pcma" => (Frequency::EIGHT_KHZ, 160),
        _ => (Frequency::FORTY_EIGHT_KHZ, 960),
    }
}

fn codec_key(codec: &str) -> Option<&'static str> {
    if codec.starts_with("pcmu/") { Some("pcmu") }
    else if codec.starts_with("pcma/") { Some("pcma") }
    else if codec.starts_with("opus/") { Some("opus") }
    else { None }
}

fn codec_name(pt: u8, rx: &[(u8, String)], fallback: &str) -> String {
    if let Some((_, name)) = rx.iter().find(|(have, _)| *have == pt) {
        return name.clone();
    }
    match pt {
        0 => "pcmu".into(),
        8 => "pcma".into(),
        _ => fallback.to_string(),
    }
}

fn ice_name(state: IceConnectionState) -> &'static str {
    match state {
        IceConnectionState::New => "new",
        IceConnectionState::Checking => "checking",
        IceConnectionState::Connected => "connected",
        IceConnectionState::Completed => "completed",
        IceConnectionState::Disconnected => "disconnected",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(a: &mut Peer, b: &mut Peer) -> Result<(), String> {
        let left = a.drain()?;
        let right = b.drain()?;
        for packet in left.transmits {
            b.receive(packet.source, packet.destination, &packet.contents)?;
        }
        for packet in right.transmits {
            a.receive(packet.source, packet.destination, &packet.contents)?;
        }
        Ok(())
    }

    fn pump(a: &mut Peer, b: &mut Peer, rounds: usize) -> Result<(), String> {
        for _ in 0..rounds {
            exchange(a, b)?;
            a.advance(Duration::from_millis(20))?;
            b.advance(Duration::from_millis(20))?;
            exchange(a, b)?;
        }
        Ok(())
    }

    fn audio_mids(events: &[ScriptEvent]) -> Vec<String> {
        events.iter().filter_map(|event| match event {
            ScriptEvent::Audio { .. } => Some("audio".into()),
            _ => None,
        }).collect()
    }

    #[test]
    fn bundled_audio_stays_on_the_same_ice_agent() {
        let mut phone = Peer::new("1.1.1.1:1000".parse().unwrap(), false).unwrap();
        let mut edge = Peer::new("2.2.2.2:2000".parse().unwrap(), false).unwrap();
        let ufrag = phone.ufrag();

        let offer = phone.create_offer().unwrap();
        assert!(offer.contains("webrtc-datachannel"), "{offer}");
        assert!(!offer.contains("m=audio"), "{offer}");
        edge.set_remote("offer", &offer).unwrap();
        let answer = edge.take_answer().unwrap();
        phone.set_remote("answer", &answer).unwrap();

        let mut dtls_dest = None;
        for _ in 0..40 {
            let left = phone.drain().unwrap();
            dtls_dest = left.transmits.last().map(|packet| packet.destination).or(dtls_dest);
            for packet in left.transmits {
                edge.receive(packet.source, packet.destination, &packet.contents).unwrap();
            }
            let right = edge.drain().unwrap();
            for packet in right.transmits {
                phone.receive(packet.source, packet.destination, &packet.contents).unwrap();
            }
            phone.advance(Duration::from_millis(20)).unwrap();
            edge.advance(Duration::from_millis(20)).unwrap();
            if phone.connected && edge.connected && edge.channel.is_some() {
                break;
            }
        }
        assert!(phone.connected && edge.connected, "dtls did not come up");
        assert!(edge.channel.is_some(), "data channel did not open");

        phone.want_audio = true;
        let audio_offer = phone.create_offer().unwrap();
        assert_eq!(phone.ufrag(), ufrag, "renegotiation opened a new ice agent");
        assert!(audio_offer.contains("m=audio"), "{audio_offer}");
        edge.set_remote("offer", &audio_offer).unwrap();
        let audio_answer = edge.take_answer().unwrap();
        phone.set_remote("answer", &audio_answer).unwrap();
        pump(&mut phone, &mut edge, 10).unwrap();
        assert!(phone.audio_mid.is_some() && edge.audio_mid.is_some(), "audio mid missing");

        let payload = super::super::codec::silence(&phone.send_codec);
        phone.write_audio(&payload).unwrap();
        let mut saw_audio = false;
        let mut rtp_dest = None;
        for _ in 0..10 {
            let drain = phone.drain().unwrap();
            rtp_dest = drain.transmits.last().map(|packet| packet.destination).or(rtp_dest);
            for packet in drain.transmits {
                edge.receive(packet.source, packet.destination, &packet.contents).unwrap();
            }
            let back = edge.drain().unwrap();
            if back.events.iter().any(|event| matches!(event, ScriptEvent::Audio { .. })) {
                saw_audio = true;
                break;
            }
            phone.advance(Duration::from_millis(20)).unwrap();
            edge.advance(Duration::from_millis(20)).unwrap();
        }
        assert!(saw_audio, "no rtp on the answerer");
        if let (Some(before), Some(after)) = (dtls_dest, rtp_dest) {
            assert_eq!(before, after, "audio left on a different socket than dtls");
        }

        let before = phone.tx_ssrc_label();
        let mid = phone.audio_mid;
        phone.rotate_ssrc().unwrap();
        assert_ne!(phone.tx_ssrc_label(), before, "ssrc did not change");
        assert_eq!(phone.audio_mid, mid);
        phone.write_audio(&payload).unwrap();
        let mut same_mid = false;
        for _ in 0..10 {
            let drain = phone.drain().unwrap();
            for packet in drain.transmits {
                edge.receive(packet.source, packet.destination, &packet.contents).unwrap();
            }
            let back = edge.drain().unwrap();
            if audio_mids(&back.events).iter().any(|_| edge.audio_mid == mid || edge.audio_mid.is_some())
                && back.events.iter().any(|event| matches!(event, ScriptEvent::Audio { .. }))
            {
                same_mid = edge.audio_mid.is_some();
                break;
            }
            phone.advance(Duration::from_millis(20)).unwrap();
        }
        assert!(same_mid, "ssrc change was not delivered on the existing mid");
    }

    /// The phone's RING offer is narrowed to PCMU/PCMA/telephone-event before
    /// setRemote. Opus-only str0m answers that with `m=audio 0`.
    #[test]
    fn g711_ring_renegotiation_keeps_audio() {
        let mut phone = Peer::new("1.1.1.1:1000".parse().unwrap(), false).unwrap();
        let mut edge = Peer::new("2.2.2.2:2000".parse().unwrap(), false).unwrap();
        let offer = phone.create_offer().unwrap();
        edge.set_remote("offer", &offer).unwrap();
        phone.set_remote("answer", &edge.take_answer().unwrap()).unwrap();
        for _ in 0..40 {
            exchange(&mut phone, &mut edge).unwrap();
            phone.advance(Duration::from_millis(20)).unwrap();
            edge.advance(Duration::from_millis(20)).unwrap();
            if phone.connected && edge.connected && edge.channel.is_some() {
                break;
            }
        }
        assert!(edge.channel.is_some(), "data channel did not open");

        phone.want_audio = true;
        let audio_offer = keep_g711(&phone.create_offer().unwrap());
        assert!(
            audio_offer.to_ascii_lowercase().contains("pcmu/8000"),
            "local offer had no pcmu to narrow: {audio_offer}"
        );
        edge.set_remote("offer", &audio_offer).unwrap();
        let answer = edge.take_answer().unwrap();
        let lower = answer.to_ascii_lowercase();
        assert!(lower.contains("pcmu/8000"), "{answer}");
        assert!(lower.contains("telephone-event/8000"), "{answer}");
        assert_ne!(audio_port(&answer), Some(0), "{answer}");
        assert!(
            bundle_contains_audio(&answer),
            "audio mid missing from BUNDLE: {answer}"
        );
        edge.drain().unwrap();
        assert!(edge.audio_mid.is_some(), "no audio mid after g711 answer");
    }

    fn keep_g711(sdp: &str) -> String {
        let allowed = ["0", "8", "110", "126"];
        let mut out = Vec::new();
        let mut in_audio = false;
        for line in sdp.lines() {
            if line.starts_with("m=") {
                in_audio = line.starts_with("m=audio ");
                if in_audio {
                    let mut parts = line.split_whitespace();
                    let media = parts.next().unwrap_or("m=audio");
                    let port = parts.next().unwrap_or("9");
                    let proto = parts.next().unwrap_or("UDP/TLS/RTP/SAVPF");
                    let pts: Vec<&str> = parts.filter(|pt| allowed.contains(pt)).collect();
                    let body = if pts.is_empty() {
                        "0 8".to_string()
                    } else {
                        pts.join(" ")
                    };
                    out.push(format!("{media} {port} {proto} {body}"));
                    continue;
                }
            }
            if in_audio
                && (line.starts_with("a=rtpmap:")
                    || line.starts_with("a=fmtp:")
                    || line.starts_with("a=rtcp-fb:"))
            {
                let rest = line.split(':').nth(1).unwrap_or("");
                let pt = rest.split([' ', '/']).next().unwrap_or("");
                if !allowed.contains(&pt) {
                    continue;
                }
            }
            out.push(line.to_string());
        }
        let mut text = out.join("\r\n");
        text.push_str("\r\n");
        text
    }

    fn audio_port(sdp: &str) -> Option<u16> {
        sdp.lines().find_map(|line| {
            let rest = line.trim().strip_prefix("m=audio ")?;
            rest.split_whitespace().next()?.parse().ok()
        })
    }

    fn bundle_contains_audio(sdp: &str) -> bool {
        let bundle: Vec<String> = sdp
            .lines()
            .find_map(|line| line.trim().strip_prefix("a=group:BUNDLE "))
            .unwrap_or("")
            .split_whitespace()
            .map(|mid| mid.to_string())
            .collect();
        let mut in_audio = false;
        let mut audio_mid = None;
        for line in sdp.lines() {
            if line.starts_with("m=") {
                in_audio = line.starts_with("m=audio ");
            }
            if in_audio {
                if let Some(mid) = line.trim().strip_prefix("a=mid:") {
                    audio_mid = Some(mid.trim().to_string());
                    break;
                }
            }
        }
        audio_mid.is_some_and(|mid| bundle.iter().any(|item| item == &mid))
    }

    #[test]
    fn end_call_offer_then_redial_accepts_the_answer() {
        let mut phone = Peer::new("1.1.1.1:1000".parse().unwrap(), false).unwrap();
        let mut edge = Peer::new("2.2.2.2:2000".parse().unwrap(), false).unwrap();
        edge.set_remote("offer", &phone.create_offer().unwrap()).unwrap();
        phone.set_remote("answer", &edge.take_answer().unwrap()).unwrap();

        phone.want_audio = true;
        let audio = phone.create_offer().unwrap();
        assert!(audio.contains("m=audio"), "{audio}");
        edge.set_remote("offer", &audio).unwrap();
        let first_answer = edge.take_answer().unwrap();
        phone.set_remote("answer", &first_answer).unwrap();
        phone.drain().unwrap();
        edge.drain().unwrap();
        assert!(phone.audio_mid.is_some(), "audio mid missing after the first offer");

        phone.arm_inactive_audio();
        let end_offer = phone.create_offer().unwrap();
        assert!(end_offer.contains("a=inactive"), "{end_offer}");
        edge.set_remote("offer", &end_offer).unwrap();
        phone.set_remote("answer", &edge.take_answer().unwrap()).unwrap();

        let redial = phone.create_offer_with(true).unwrap();
        assert!(redial.contains("m=audio"), "{redial}");
        assert!(!redial.contains("a=inactive"), "{redial}");
        assert_eq!(
            ice_ufrag(&end_offer),
            ice_ufrag(&redial),
            "redial restarted ice\n{redial}"
        );
        edge.set_remote_ex("offer", &redial, true).unwrap();
        let redial_answer = edge.take_answer().unwrap();
        let first_ssrc = first_answer.lines().find(|line| line.starts_with("a=ssrc:"));
        let redial_ssrc = redial_answer.lines().find(|line| line.starts_with("a=ssrc:"));
        assert_ne!(first_ssrc, redial_ssrc, "redial answer reused the first SSRC\n{redial_answer}");
        assert!(redial_answer.contains("a=sendrecv"), "{redial_answer}");
        phone.set_remote("answer", &redial_answer).unwrap();

        // The server is the answerer of the phone's end-call, then it offers
        // the redial. That offer has to be sendrecv or the phone ignores it.
        edge.arm_inactive_audio();
        let end_from_edge = edge.create_offer().unwrap();
        phone.set_remote("offer", &end_from_edge).unwrap();
        edge.set_remote("answer", &phone.take_answer().unwrap()).unwrap();
        let from_answerer = edge.create_offer_with(true).unwrap();
        assert!(from_answerer.contains("a=sendrecv"), "{from_answerer}");
        assert!(!audio_section_inactive(&from_answerer), "{from_answerer}");
        assert_eq!(
            ice_ufrag(&end_from_edge),
            ice_ufrag(&from_answerer),
            "redial restarted ice\n{from_answerer}"
        );
    }
}

fn ice_ufrag(sdp: &str) -> Option<&str> {
    sdp.lines().find_map(|line| line.trim().strip_prefix("a=ice-ufrag:"))
}

fn offer_sends_audio(sdp: &str) -> bool {
    let mut in_audio = false;
    for line in sdp.lines() {
        let line = line.trim();
        if line.starts_with("m=") {
            in_audio = line.starts_with("m=audio ");
            continue;
        }
        if in_audio && (line == "a=sendrecv" || line == "a=sendonly") {
            return true;
        }
    }
    false
}

fn audio_section_inactive(sdp: &str) -> bool {
    let mut in_audio = false;
    for line in sdp.lines() {
        let line = line.trim();
        if line.starts_with("m=") {
            if in_audio {
                return false;
            }
            in_audio = line.starts_with("m=audio ");
            continue;
        }
        if !in_audio {
            continue;
        }
        if line == "a=sendrecv" || line == "a=sendonly" {
            return false;
        }
        if line == "a=inactive" || line == "a=recvonly" {
            return true;
        }
    }
    false
}
