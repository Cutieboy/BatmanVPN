#![doc = "Temporary field diagnostics for the split tunnel."]
#![cfg_attr(not(windows), allow(dead_code))]
//!
//! # This module is scaffolding
//!
//! It exists to answer one question on real machines — how much traffic
//! actually crosses the tunnel, how far away the server is, and how much is
//! lost on the way — and is meant to be deleted once that question is
//! answered. Removing it is this file, its `mod` line, and the call sites in
//! [`crate::split_tunnel`].
//!
//! Everything it emits goes to stderr as `MOUSEVPN_DIAG=` lines, which the
//! desktop application already copies verbatim into
//! `%LOCALAPPDATA%\MouseVPN\logs\helper.log`. Nothing in the installer or the
//! packaging has to change for the numbers to reach a user's log.
//!
//! Set `MOUSEVPN_DIAG=0` in the helper's environment to silence it without
//! rebuilding.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

/// How often a summary line is emitted.
const REPORT_INTERVAL: Duration = Duration::from_secs(5);

/// How far behind the highest sequence a datagram may arrive and still count
/// as reordering rather than a session that started numbering again.
///
/// Ordinary reordering spans a handful of datagrams. A session restart drops
/// the sequence from wherever it had reached back to zero, which no path can
/// produce by delaying packets.
const REORDER_WINDOW: u64 = 4_096;

/// Counters the capture thread writes and the reporting thread reads.
///
/// Only the sending side is shared: capture runs on its own thread, while
/// every receive-side number below is touched by the receive loop alone and
/// needs no synchronisation at all.
#[derive(Default)]
pub(crate) struct SendCounters {
    packets: AtomicU64,
    bytes: AtomicU64,
    failed: AtomicU64,
}

impl SendCounters {
    /// Records one packet handed to the transport.
    pub(crate) fn sent(&self, bytes: usize) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Records one packet that never reached the wire.
    pub(crate) fn failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.packets.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
            self.failed.load(Ordering::Relaxed),
        )
    }
}

/// Round-trip times observed over one reporting interval, in microseconds.
#[derive(Default)]
struct Rtt {
    last: u64,
    min: u64,
    max: u64,
    total: u64,
    count: u64,
}

impl Rtt {
    fn record(&mut self, elapsed: Duration) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.last = micros;
        self.min = if self.count == 0 {
            micros
        } else {
            self.min.min(micros)
        };
        self.max = self.max.max(micros);
        self.total = self.total.saturating_add(micros);
        self.count = self.count.saturating_add(1);
    }

    fn average(&self) -> u64 {
        self.total / self.count.max(1)
    }
}

/// Tracks gaps in the protocol's per-datagram sequence.
///
/// The header numbers every datagram the server sends, so a gap is a datagram
/// that did not arrive. This measures loss on the path from the server to this
/// machine only. Loss in the other direction is invisible from here, and
/// reporting a number for it would be guesswork.
#[derive(Default)]
struct Sequence {
    /// One past the highest sequence seen, so zero means nothing yet.
    highest: u64,
    received: u64,
    /// The two values above as of the previous report.
    reported_highest: u64,
    reported_received: u64,
}

impl Sequence {
    fn observe(&mut self, sequence: u64) {
        // A reconnect starts a session whose numbering restarts at zero.
        // Without this its first datagram reads as millions of losses, at the
        // exact moment someone is reading the log to find out why the tunnel
        // dropped. The window is what keeps a merely late datagram from
        // triggering the same reset and discarding a real measurement.
        let position = sequence.saturating_add(1);
        if self.highest.saturating_sub(position) > REORDER_WINDOW {
            self.restart();
        }
        self.highest = self.highest.max(position);
        self.received = self.received.saturating_add(1);
    }

    fn restart(&mut self) {
        self.highest = 0;
        self.received = 0;
        self.reported_highest = 0;
        self.reported_received = 0;
    }

    /// Returns the datagrams expected and the ones missing since the last
    /// report, the way RTP measures loss: a datagram that arrives late simply
    /// closes its gap in a later interval.
    fn interval(&mut self) -> (u64, u64) {
        let expected = self.highest.saturating_sub(self.reported_highest);
        let received = self.received.saturating_sub(self.reported_received);
        self.reported_highest = self.highest;
        self.reported_received = self.received;
        (expected, expected.saturating_sub(received))
    }
}

/// Collects and prints the session's traffic, latency and loss.
pub(crate) struct Diagnostics {
    enabled: bool,
    reported: Instant,
    sent: (u64, u64, u64),
    packets: u64,
    bytes: u64,
    rejected: u64,
    probes_sent: u64,
    probes_answered: u64,
    outstanding: Option<Instant>,
    rtt: Rtt,
    sequence: Sequence,
}

impl Diagnostics {
    /// Starts collecting unless `MOUSEVPN_DIAG` switches it off.
    pub(crate) fn start() -> Self {
        let enabled = !matches!(
            std::env::var("MOUSEVPN_DIAG").as_deref(),
            Ok("0" | "off" | "false")
        );
        if enabled {
            eprintln!(
                "MOUSEVPN_DIAG=started interval_s={} note=set MOUSEVPN_DIAG=0 to silence",
                REPORT_INTERVAL.as_secs()
            );
        }
        Self {
            enabled,
            reported: Instant::now(),
            sent: (0, 0, 0),
            packets: 0,
            bytes: 0,
            rejected: 0,
            probes_sent: 0,
            probes_answered: 0,
            outstanding: None,
            rtt: Rtt::default(),
            sequence: Sequence::default(),
        }
    }

    /// Records one datagram accepted from the server.
    pub(crate) fn received(&mut self, sequence: u64, bytes: usize) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes as u64);
        self.sequence.observe(sequence);
    }

    /// Records one datagram that failed to decode or authenticate.
    ///
    /// This is not path loss: the datagram arrived. It is either a stale
    /// session's traffic or something on the path rewriting bytes, and telling
    /// those apart from loss is the reason it is counted separately.
    pub(crate) fn rejected(&mut self) {
        self.rejected = self.rejected.saturating_add(1);
    }

    /// Marks a keepalive as sent, starting the round-trip clock.
    pub(crate) fn probe_sent(&mut self, now: Instant) {
        self.probes_sent = self.probes_sent.saturating_add(1);
        // An unanswered probe is abandoned rather than measured late: the
        // reply to this one would otherwise be timed against the older send
        // and report a round trip that never happened.
        self.outstanding = Some(now);
    }

    /// Closes the round trip when the server's keepalive comes back.
    pub(crate) fn probe_answered(&mut self, now: Instant) {
        let Some(sent) = self.outstanding.take() else {
            return;
        };
        self.probes_answered = self.probes_answered.saturating_add(1);
        self.rtt.record(now.saturating_duration_since(sent));
    }

    /// Forgets everything the previous session measured.
    pub(crate) fn session_restarted(&mut self) {
        self.sequence.restart();
        self.outstanding = None;
    }

    /// Emits one summary line once the interval has elapsed.
    pub(crate) fn report(&mut self, counters: &SendCounters) {
        if !self.enabled || self.reported.elapsed() < REPORT_INTERVAL {
            return;
        }
        self.reported = Instant::now();
        let sent = counters.snapshot();
        let up_packets = sent.0.saturating_sub(self.sent.0);
        let up_bytes = sent.1.saturating_sub(self.sent.1);
        let up_failed = sent.2.saturating_sub(self.sent.2);
        self.sent = sent;
        let (expected, lost) = self.sequence.interval();

        eprintln!(
            "MOUSEVPN_DIAG=up_pkt={up_packets} up_kb={} up_fail={up_failed} \
             down_pkt={} down_kb={} down_lost={lost}/{expected} down_loss_pct={} \
             down_bad={} ping_ms={} ping_min={} ping_max={} probes={}/{}",
            up_bytes / 1024,
            self.packets,
            self.bytes / 1024,
            percent(lost, expected),
            self.rejected,
            millis(self.rtt.average()),
            millis(self.rtt.min),
            millis(self.rtt.max),
            self.probes_answered,
            self.probes_sent,
        );

        self.packets = 0;
        self.bytes = 0;
        self.rejected = 0;
        self.probes_sent = 0;
        self.probes_answered = 0;
        self.rtt = Rtt::default();
    }
}

/// Formats microseconds as milliseconds with one decimal, in integers.
///
/// A float here would be the only lossy cast on this path, and the value is
/// read by eye either way.
fn millis(micros: u64) -> String {
    let tenths = micros / 100;
    format!("{}.{}", tenths / 10, tenths % 10)
}

/// Formats a ratio as a percentage with one decimal, in integers.
fn percent(part: u64, whole: u64) -> String {
    if whole == 0 {
        return "0.0".to_owned();
    }
    let tenths = part.saturating_mul(1_000) / whole;
    format!("{}.{}", tenths / 10, tenths % 10)
}

#[cfg(test)]
mod tests {
    use super::{millis, percent, Diagnostics, SendCounters, Sequence};
    use std::time::{Duration, Instant};

    #[test]
    fn counts_the_gaps_between_sequence_numbers() {
        let mut sequence = Sequence::default();
        for observed in [0, 1, 2, 5, 6] {
            sequence.observe(observed);
        }
        // Seven were sent and five arrived: three and four are missing.
        assert_eq!(sequence.interval(), (7, 2));
    }

    #[test]
    fn reports_nothing_lost_once_a_gap_is_filled_late() {
        let mut sequence = Sequence::default();
        sequence.observe(0);
        sequence.observe(2);
        assert_eq!(sequence.interval(), (3, 1));
        // The straggler arrives in the next interval and closes the gap, so
        // reordering must not accumulate as loss.
        sequence.observe(1);
        sequence.observe(3);
        assert_eq!(sequence.interval(), (1, 0));
    }

    #[test]
    fn reordering_alone_never_restarts_the_measurement() {
        // A datagram that merely arrives late must not be mistaken for a new
        // session: treating it that way throws away the interval it belongs
        // to and reports loss that did not happen.
        let mut sequence = Sequence::default();
        sequence.observe(4_000);
        let _ = sequence.interval();
        sequence.observe(3_999);
        assert_eq!(sequence.highest, 4_001);
    }

    #[test]
    fn a_restarted_session_does_not_read_as_mass_loss() {
        let mut sequence = Sequence::default();
        sequence.observe(9_000);
        let _ = sequence.interval();
        sequence.observe(0);
        sequence.observe(1);
        assert_eq!(sequence.interval(), (2, 0));
    }

    #[test]
    fn times_a_probe_only_against_its_own_send() {
        let mut diagnostics = Diagnostics::start();
        let start = Instant::now();
        diagnostics.probe_sent(start);
        diagnostics.probe_answered(start + Duration::from_millis(40));
        assert_eq!(diagnostics.rtt.count, 1);
        assert_eq!(millis(diagnostics.rtt.last), "40.0");
        // A reply with no probe outstanding measures nothing.
        diagnostics.probe_answered(start + Duration::from_secs(9));
        assert_eq!(diagnostics.rtt.count, 1);
    }

    #[test]
    fn an_unanswered_probe_is_dropped_rather_than_timed_late() {
        let mut diagnostics = Diagnostics::start();
        let start = Instant::now();
        diagnostics.probe_sent(start);
        diagnostics.probe_sent(start + Duration::from_secs(3));
        diagnostics.probe_answered(start + Duration::from_millis(3_050));
        // Timed against the second probe, not the first one that went missing.
        assert_eq!(millis(diagnostics.rtt.last), "50.0");
        assert_eq!(diagnostics.probes_sent, 2);
        assert_eq!(diagnostics.probes_answered, 1);
    }

    #[test]
    fn accumulates_sending_counters_across_threads() {
        let counters = SendCounters::default();
        counters.sent(1_200);
        counters.sent(300);
        counters.failed();
        assert_eq!(counters.snapshot(), (2, 1_500, 1));
    }

    #[test]
    fn formats_without_floating_point() {
        assert_eq!(millis(24_350), "24.3");
        assert_eq!(millis(0), "0.0");
        assert_eq!(percent(1, 1_000), "0.1");
        assert_eq!(percent(0, 0), "0.0");
        assert_eq!(percent(5, 10), "50.0");
    }
}
