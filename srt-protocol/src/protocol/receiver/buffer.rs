use std::{
    cmp::min,
    collections::VecDeque,
    convert::TryFrom,
    ops::Range,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};

use crate::{options::PacketCount, packet::*};

use super::{
    time::{ClockAdjustment, SynchronizedRemoteClock},
    DataPacketAction, DataPacketError,
};

#[derive(Debug)]
pub struct LostPacket {
    data_sequence_number: SeqNumber,
    feedback_time: Instant,
    k: i32,
    /// While set, the gap is still within the reorder tolerance: no loss
    /// report goes out until a packet with at least this sequence number
    /// has arrived (in the hope that the missing packet is merely late).
    fresh_until: Option<SeqNumber>,
}

impl LostPacket {
    pub fn new(data_sequence_number: SeqNumber, feedback_time: Instant) -> Self {
        Self {
            data_sequence_number,
            feedback_time,
            k: 2,
            fresh_until: None,
        }
    }
}

#[derive(Debug)]
pub enum BufferPacket {
    Lost(LostPacket),
    Received(DataPacket),
    Dropped(SeqNumber),
}

impl BufferPacket {
    pub fn data_sequence_number(&self) -> SeqNumber {
        match self {
            BufferPacket::Lost(LostPacket {
                data_sequence_number: seq_number,
                ..
            })
            | BufferPacket::Dropped(seq_number)
            | BufferPacket::Received(DataPacket { seq_number, .. }) => *seq_number,
        }
    }

    pub fn data_packet(&self) -> Option<&DataPacket> {
        match self {
            BufferPacket::Received(data) => Some(data),
            _ => None,
        }
    }

    pub fn into_data_packet(self) -> Option<DataPacket> {
        match self {
            BufferPacket::Received(data) => Some(data),
            _ => None,
        }
    }

    pub fn in_message(&self, message: MsgNumber) -> bool {
        self.data_packet()
            .map_or(false, |d| d.message_number == message)
    }

    pub fn is_first(&self) -> bool {
        matches!(self, BufferPacket::Received(data) if data.message_loc.contains(PacketLocation::FIRST))
    }

    fn lost_or_dropped(&self) -> Option<SeqNumber> {
        match self {
            BufferPacket::Lost(LostPacket {
                data_sequence_number: sn,
                ..
            })
            | BufferPacket::Dropped(sn) => Some(*sn),
            _ => None,
        }
    }

    pub fn lost_ready_for_feedback_mut(
        &mut self,
        now: Instant,
        rtt_mean: TimeSpan,
    ) -> Option<&mut LostPacket> {
        match self {
            BufferPacket::Lost(lost) if now > lost.feedback_time + (rtt_mean * lost.k) => {
                Some(lost)
            }
            _ => None,
        }
    }

    pub fn update_data(&mut self, data: DataPacket) -> Result<(), DataPacketError> {
        use BufferPacket::*;
        if matches!(self, Lost(_)) {
            *self = Received(data);
            Ok(())
        } else {
            Err(DataPacketError::DiscardedDuplicate {
                seq_number: data.seq_number,
            })
        }
    }

    pub fn drop_unreceived(&mut self) -> Option<SeqNumber> {
        use BufferPacket::*;
        let dsn = self.data_sequence_number();
        if matches!(self, Lost(_)) {
            *self = Dropped(dsn);
            Some(dsn)
        } else {
            None
        }
    }
}

pub struct MessagePacketCount {
    count: usize,
    done: bool,
}

impl MessagePacketCount {
    pub fn new() -> Self {
        Self {
            count: 0,
            done: false,
        }
    }

    pub fn accumulate(mut self, packet: &BufferPacket) -> Option<Self> {
        let location = packet.data_packet()?.message_loc;
        if !self.done {
            if self.count == 0 && !location.contains(PacketLocation::FIRST) {
                return None;
            }
            if location.contains(PacketLocation::LAST) {
                self.done = true;
            }
            self.count += 1;
        }
        Some(self)
    }

    pub fn calculate(self) -> Option<usize> {
        if self.done {
            Some(self.count)
        } else {
            None
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct MessageError {
    pub too_late_packets: Range<SeqNumber>,
    pub delay: TimeSpan,
}

#[derive(Debug)]
pub struct ReceiveBuffer {
    tsbpd_latency: Duration,
    /// Adds an extra delay to the TSBPD threshold for dropping too late packets
    tsbpd_tolerance: Duration,

    // Sequence number that all packets up to have been received + 1
    lrsn: SeqNumber,

    // first sequence number in the list
    seqno0: SeqNumber,

    too_late_packet_drop: bool,
    remote_clock: SynchronizedRemoteClock,
    buffer: VecDeque<BufferPacket>,
    max_buffer_size: PacketCount,

    /// SRTO_LOSSMAXTTL, the reorder tolerance's ceiling; 0 turns it off.
    reorder_tolerance_max: u32,
    /// How many packets must follow a gap before it is reported as loss.
    /// Starts at 0 and follows the reordering actually seen.
    reorder_tolerance: u32,
    /// In-order arrivals since the last reordering.
    in_order_run: u32,
    /// The oldest lost packet that is still waiting out the tolerance.
    fresh_from: Option<SeqNumber>,
}

/// Consecutive in-order packets after which the reorder tolerance shrinks by
/// one, as in libsrt.
const REORDER_DECAY_PACKETS: u32 = 50;

impl ReceiveBuffer {
    pub fn new(
        socket_start_time: Instant,
        tsbpd_latency: Duration,
        too_late_packet_drop: bool,
        init_seq_num: SeqNumber,
        max_buffer_size: PacketCount,
    ) -> Self {
        Self {
            tsbpd_latency,
            // TODO: perhaps make this configurable
            tsbpd_tolerance: Duration::from_millis(5),
            too_late_packet_drop,
            lrsn: init_seq_num,
            seqno0: init_seq_num,
            remote_clock: SynchronizedRemoteClock::new(socket_start_time),
            buffer: VecDeque::with_capacity(max_buffer_size.into()),
            max_buffer_size,
            reorder_tolerance_max: 0,
            reorder_tolerance: 0,
            in_order_run: 0,
            fresh_from: None,
        }
    }

    /// Lets the reorder tolerance grow up to `max` packets (SRTO_LOSSMAXTTL).
    pub fn with_reorder_tolerance_max(mut self, max: PacketCount) -> Self {
        self.reorder_tolerance_max = u32::try_from(max.0).unwrap_or(u32::MAX);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Data Sequence Number of the packet following the last acknowledged packet
    pub fn next_ack_dsn(&self) -> SeqNumber {
        self.lrsn
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
        self.fresh_from = None;
    }

    pub fn synchronize_clock(
        &mut self,
        now: Instant,
        now_ts: TimeStamp,
    ) -> Option<ClockAdjustment> {
        self.remote_clock.synchronize(now, now_ts)
    }

    /// Buffer available, in packets
    pub fn buffer_available(&self) -> usize {
        usize::from(self.max_buffer_size) - self.buffer.len()
    }

    // next expected packet (1 + last received packet)
    fn next_packet_dsn(&self) -> SeqNumber {
        self.seqno0 + u32::try_from(self.buffer.len()).unwrap()
    }

    // index in buffer for a given sequence number
    // returns None if before the start of the buffer. Might return a index out of bounds
    fn index_for_seqno(&self, seq_number: SeqNumber) -> Option<usize> {
        if seq_number < self.seqno0 {
            None
        } else {
            Some((seq_number - self.seqno0) as usize)
        }
    }

    // index in buffer for a given sequence number clamped to 0 or buffer.len()
    fn clamped_index_for_seqno(&self, seq_number: SeqNumber) -> usize {
        min(seq_number.saturating_sub(self.seqno0), self.buffer.len())
    }

    pub fn push_packet(
        &mut self,
        now: Instant,
        data: DataPacket,
    ) -> Result<DataPacketAction, DataPacketError> {
        use std::cmp::Ordering::*;
        match data.seq_number.cmp(&self.next_packet_dsn()) {
            Equal => self.append_next(now, data),
            Greater => self.append_with_loss(now, data),
            Less => self.recover_data(data),
        }
    }

    pub fn pop_next_message(
        &mut self,
        now: Instant,
    ) -> Result<Option<(Instant, Bytes)>, MessageError> {
        let timestamp = match self.front_ts() {
            Some(timestamp) => timestamp,
            None => return self.drop_too_late_packets(now),
        };

        let sent_time = self.remote_clock.instant_from(timestamp);
        if now < sent_time + self.tsbpd_latency {
            return Ok(None);
        }

        let packet_count = match self.next_message_packet_count() {
            Some(packet_count) => packet_count,
            None => return self.drop_too_late_packets(now),
        };

        self.seqno0 += u32::try_from(packet_count).unwrap();

        let release_time = self.remote_clock.monotonic_instant_from(timestamp);
        let message = if packet_count == 1 {
            self.release_single_packet_message(release_time)
        } else {
            self.release_full_message(release_time, packet_count)
        };
        Ok(message)
    }

    fn front_ts(&mut self) -> Option<TimeStamp> {
        self.buffer.front()?.data_packet().map(|d| d.timestamp)
    }

    fn release_single_packet_message(&mut self, release_time: Instant) -> Option<(Instant, Bytes)> {
        Some((
            release_time,
            self.buffer.pop_front()?.into_data_packet()?.payload,
        ))
    }

    fn release_full_message(
        &mut self,
        release_time: Instant,
        packet_count: usize,
    ) -> Option<(Instant, Bytes)> {
        Some((
            release_time,
            self.buffer
                .drain(0..packet_count)
                .fold(BytesMut::new(), |mut bytes, pack| {
                    bytes.extend(pack.into_data_packet().unwrap().payload);
                    bytes
                })
                .freeze(),
        ))
    }

    pub fn prepare_loss_list(
        &mut self,
        now: Instant,
        rtt_mean: TimeSpan,
    ) -> Option<CompressedLossList> {
        // Search the receiver's loss list, find out all those sequence numbers
        // whose last feedback time is k*RTT before, where k is initialized as 2
        // and increased by 1 each time the number is fed back. Compress
        // (according to section 6.4) and send these numbers back to the sender
        // in an NAK packet.
        let loss_list = self
            .buffer
            .range_mut(self.lost_list_index()..)
            .filter_map(|p| p.lost_ready_for_feedback_mut(now, rtt_mean))
            .map(|lost| {
                // increment k and change feedback time, returning sequence numbers
                lost.k += 1;
                lost.feedback_time = now;
                lost.fresh_until = None;
                lost.data_sequence_number
            });

        CompressedLossList::try_from_iter(loss_list)
    }

    /// Returns how many packets were actually dropped
    pub fn drop_packets(&mut self, range: Range<SeqNumber>) -> usize {
        // if start of the range has been dropped already, just drop everything after
        let first_idx = self.clamped_index_for_seqno(range.start);
        let last_idx = self.clamped_index_for_seqno(range.end);
        if first_idx >= last_idx {
            return 0;
        }
        self.buffer
            .range_mut(first_idx..last_idx)
            .filter_map(|p| p.drop_unreceived())
            .count()
    }

    pub fn next_message_release_time(&self) -> Option<Instant> {
        self.buffer
            .front()
            .filter(|p| p.is_first())?
            .data_packet()
            .map(|d| self.remote_clock.instant_from(d.timestamp) + self.tsbpd_latency)
    }

    fn append_next(
        &mut self,
        now: Instant,
        data: DataPacket,
    ) -> Result<DataPacketAction, DataPacketError> {
        if self.buffer_available() == 0 {
            Err(DataPacketError::BufferFull {
                seq_number: data.seq_number,
                buffer_size: self.buffer.len(),
            })
        } else {
            let seq_number = data.seq_number;
            self.append_data(data);
            self.decay_reorder_tolerance();
            let expired = self.expire_fresh_losses(now, seq_number);
            Ok(
                match CompressedLossList::try_from_iter(expired.into_iter()) {
                    Some(loss_list) => DataPacketAction::ReceivedWithLoss(loss_list),
                    None => DataPacketAction::Received {
                        lrsn: self.lrsn,
                        recovered: false,
                    },
                },
            )
        }
    }

    fn append_with_loss(
        &mut self,
        now: Instant,
        data: DataPacket,
    ) -> Result<DataPacketAction, DataPacketError> {
        let seq_number = data.seq_number;
        let lost = self.next_packet_dsn()..seq_number;
        let lost_count = lost.end - lost.start;

        // avoid buffer overrun
        let buffer_required = usize::try_from(lost_count).unwrap() + 1; // +1 to store the packet itself
        let buffer_available = self.buffer_available();
        if buffer_available < buffer_required {
            Err(DataPacketError::PacketTooEarly {
                seq_number,
                buffer_available,
                buffer_required,
            })
        } else {
            // Older gaps whose tolerance ran out with this packet are reported too.
            let mut report = self.expire_fresh_losses(now, seq_number);
            let fresh_until =
                (self.reorder_tolerance > 0).then(|| seq_number + self.reorder_tolerance);
            self.append_lost_packets(now, &lost, fresh_until);
            self.append_data(data);

            let loss_list = if fresh_until.is_some() {
                CompressedLossList::try_from_iter(report.into_iter())
            } else if report.is_empty() {
                Some(lost.into())
            } else {
                report.extend((0..lost_count).map(|i| lost.start + i));
                CompressedLossList::try_from_iter(report.into_iter())
            };
            Ok(match loss_list {
                Some(loss_list) => DataPacketAction::ReceivedWithLoss(loss_list),
                None => DataPacketAction::Received {
                    lrsn: self.lrsn,
                    recovered: false,
                },
            })
        }
    }

    fn recover_data(&mut self, data: DataPacket) -> Result<DataPacketAction, DataPacketError> {
        let seq_number = data.seq_number;
        let index = self
            .index_for_seqno(seq_number)
            .ok_or(DataPacketError::PacketTooLate {
                seq_number,
                seq_number_0: self.seqno0,
            })?;

        let retransmitted = data.retransmitted;
        self.buffer.get_mut(index).unwrap().update_data(data)?;

        // An original (not retransmitted) packet that turns up behind a
        // newer one was reordered, not lost: tolerate that much next time.
        if !retransmitted {
            let distance = self.next_packet_dsn() - seq_number - 1;
            self.grow_reorder_tolerance(distance);
        }

        // first lost packet was recovered, update LRSN
        if self.lrsn == seq_number {
            self.recalculate_lrsn(index);
        }
        Ok(DataPacketAction::Received {
            lrsn: self.lrsn,
            recovered: true,
        })
    }

    fn append_data(&mut self, data: DataPacket) {
        let seq_number = data.seq_number;
        if self.lrsn == seq_number {
            self.lrsn = seq_number + 1;
        }
        self.buffer.push_back(BufferPacket::Received(data));
    }

    fn append_lost_packets(
        &mut self,
        now: Instant,
        lost: &Range<SeqNumber>,
        fresh_until: Option<SeqNumber>,
    ) {
        let lost_count = lost.end - lost.start;
        for i in 0..lost_count {
            let mut loss = LostPacket::new(lost.start + i, now);
            loss.fresh_until = fresh_until;
            self.buffer.push_back(BufferPacket::Lost(loss));
        }
        if fresh_until.is_some() && lost_count > 0 {
            self.fresh_from.get_or_insert(lost.start);
        }
    }

    /// Takes the lost packets whose reorder tolerance has run out now that
    /// `highest` has arrived; they are due a loss report.
    fn expire_fresh_losses(&mut self, now: Instant, highest: SeqNumber) -> Vec<SeqNumber> {
        let Some(from) = self.fresh_from else {
            return vec![];
        };
        let start = self.clamped_index_for_seqno(from);
        let mut expired = vec![];
        let mut still_fresh = None;
        for packet in self.buffer.range_mut(start..) {
            if let BufferPacket::Lost(lost) = packet {
                match lost.fresh_until {
                    Some(until) if highest < until => {
                        still_fresh.get_or_insert(lost.data_sequence_number);
                    }
                    Some(_) => {
                        lost.fresh_until = None;
                        lost.feedback_time = now;
                        expired.push(lost.data_sequence_number);
                    }
                    None => {}
                }
            }
        }
        self.fresh_from = still_fresh;
        expired
    }

    fn grow_reorder_tolerance(&mut self, distance: u32) {
        self.in_order_run = 0;
        if distance > self.reorder_tolerance {
            self.reorder_tolerance = min(distance, self.reorder_tolerance_max);
        }
    }

    fn decay_reorder_tolerance(&mut self) {
        if self.reorder_tolerance == 0 {
            return;
        }
        self.in_order_run += 1;
        if self.in_order_run >= REORDER_DECAY_PACKETS {
            self.reorder_tolerance -= 1;
            self.in_order_run = 0;
        }
    }

    fn lost_list_index(&self) -> usize {
        self.buffer
            .iter()
            .take_while(|b| b.data_packet().is_some())
            .count()
    }

    fn next_message_packet_count(&self) -> Option<usize> {
        let first = self.buffer.front()?.data_packet()?;
        self.buffer
            .iter()
            // once stabilized in std, take_while & filter_map can be replaced with map_while
            .take_while(|p| p.in_message(first.message_number))
            .try_fold(MessagePacketCount::new(), |a, p| a.accumulate(p))?
            .calculate()
    }

    /// Drops the packets that are deemed to be too late
    /// i.e.: there is a packet after it that is ready to be released
    fn drop_too_late_packets(
        &mut self,
        now: Instant,
    ) -> Result<Option<(Instant, Bytes)>, MessageError> {
        if !self.too_late_packet_drop {
            return Ok(None);
        }

        let data_packets = self.buffer.iter().map(|packet| {
            packet.data_packet().map(|data| {
                (
                    data.seq_number,
                    self.remote_clock.instant_from(data.timestamp),
                    data.message_loc,
                )
            })
        });

        let tsbpd_threshold = now - self.tsbpd_latency - self.tsbpd_tolerance;
        let too_late_packets = data_packets.take_while(|packet| {
            packet.map_or(true, |(_, packet_time, message_loc)| {
                packet_time <= tsbpd_threshold || !message_loc.contains(PacketLocation::FIRST)
            })
        });

        let dropped_packets = too_late_packets.fold(None, |last, packet| match (last, packet) {
            (None, Some((seq_number, packet_time, _))) => Some((seq_number, packet_time)),
            (Some((_, first_packet_time)), Some((seq_number, _, _))) => {
                Some((seq_number, first_packet_time))
            }
            (last, _) => last,
        });

        let (last_seq_number, first_packet_time) = match dropped_packets {
            Some(packets) => packets,
            None => return Ok(None),
        };

        let begin_packet = self.seqno0;
        let end_packet = last_seq_number + 1;
        let drop_count = end_packet.saturating_sub(begin_packet);

        self.seqno0 = end_packet;
        self.buffer.drain(0..drop_count);
        self.recalculate_lrsn(0);

        Err(MessageError {
            delay: TimeSpan::from_interval(first_packet_time + self.tsbpd_latency, now),
            too_late_packets: begin_packet..end_packet,
        })
    }

    fn recalculate_lrsn(&mut self, start_idx: usize) {
        self.lrsn = self
            .buffer
            .range(start_idx..)
            .filter_map(|p| p.lost_or_dropped())
            .next()
            .unwrap_or_else(|| self.next_packet_dsn())
    }

    pub fn rx_acknowledged_time(&self) -> Duration {
        let start_idx = 0;
        let end_idx = self.clamped_index_for_seqno(self.lrsn - 1);

        if let (Some(BufferPacket::Received(s)), Some(BufferPacket::Received(e))) =
            (self.buffer.get(start_idx), self.buffer.get(end_idx))
        {
            Duration::from_micros(
                u64::try_from((e.timestamp - s.timestamp).as_micros()).unwrap_or(0),
            )
        } else {
            Duration::from_micros(0)
        }
    }
}

#[cfg(test)]
mod receive_buffer {
    use pretty_assertions::assert_eq;

    use super::*;

    use DataPacketAction::*;
    use DataPacketError::*;

    fn basic_pack() -> DataPacket {
        DataPacket {
            seq_number: SeqNumber(1),
            message_loc: PacketLocation::ONLY,
            in_order_delivery: false,
            encryption: DataEncryption::None,
            retransmitted: false,
            message_number: MsgNumber(0),
            timestamp: TimeStamp::from_micros(0),
            dest_sockid: SocketId(4),
            payload: b"basic payload"[..].into(),
        }
    }

    #[test]
    fn not_ready_empty() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(3);

        let mut buf = ReceiveBuffer::new(start, tsbpd, true, init_seq_num, PacketCount(8192));

        assert_eq!(buf.next_ack_dsn(), init_seq_num);
        assert_eq!(buf.next_message_release_time(), None);
        assert_eq!(buf.pop_next_message(start), Ok(None));
    }

    #[test]
    fn multi_packet_message_not_ready() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, true, init_seq_num, PacketCount(8192));

        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    message_loc: PacketLocation::FIRST,
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 1);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(buf.pop_next_message(start + tsbpd), Ok(None));
    }

    #[test]
    fn multi_packet_message_lost_last_packet() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(0);

        let mut buf = ReceiveBuffer::new(start, tsbpd, true, init_seq_num, PacketCount(8192));

        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    message_loc: PacketLocation::FIRST,
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 1);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(buf.pop_next_message(start + tsbpd), Ok(None));

        // 1 lost packet
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 2,
                    message_loc: PacketLocation::FIRST,
                    ..basic_pack()
                }
            ),
            Ok(ReceivedWithLoss([init_seq_num + 1].iter().collect()))
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 1);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(
            buf.pop_next_message(start + tsbpd * 2),
            Err(MessageError {
                too_late_packets: SeqNumber(0)..SeqNumber(3),
                delay: TimeSpan::from_millis(2_000)
            })
        );
    }

    #[test]
    fn multi_packet_message_incomplete_transmission() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, true, init_seq_num, PacketCount(8192));

        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    message_loc: PacketLocation::FIRST,
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 1);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(buf.pop_next_message(start + tsbpd), Ok(None));
        assert_eq!(buf.pop_next_message(start + tsbpd), Ok(None));

        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 1,
                    message_loc: PacketLocation::empty(),
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 2,
                recovered: false
            })
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 2);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(buf.pop_next_message(start + tsbpd), Ok(None));
    }

    #[test]
    fn single_packet_message_ready() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, true, init_seq_num, PacketCount(8192));

        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    message_loc: PacketLocation::FIRST | PacketLocation::LAST,
                    payload: b"hello"[..].into(),
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 1,
                    message_loc: PacketLocation::empty(),
                    payload: b"no"[..].into(),
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 2,
                recovered: false
            })
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 2);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(
            buf.pop_next_message(start + tsbpd * 2),
            Ok(Some((start, b"hello"[..].into())))
        );
    }

    #[test]
    fn push_packet_multi_packet_message_ready() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, true, init_seq_num, PacketCount(8192));
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    message_loc: PacketLocation::FIRST,
                    payload: b"hello"[..].into(),
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 1,
                    message_loc: PacketLocation::empty(),
                    payload: b"yas"[..].into(),
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 2,
                recovered: false
            })
        );
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 2,
                    message_loc: PacketLocation::LAST,
                    payload: b"nas"[..].into(),
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 3,
                recovered: false
            })
        );
        assert_eq!(buf.next_ack_dsn(), init_seq_num + 3);
        assert_eq!(buf.next_message_release_time(), Some(start + tsbpd));
        assert_eq!(buf.pop_next_message(start), Ok(None));
        assert_eq!(
            buf.pop_next_message(start + tsbpd * 2),
            Ok(Some((start, b"helloyasnas"[..].into())))
        );

        assert_eq!(buf.buffer.len(), 0);
    }

    #[test]
    fn prepare_loss_list() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);
        let mean_rtt = TimeSpan::from_micros(10_000);

        let mut buf = ReceiveBuffer::new(start, tsbpd, true, init_seq_num, PacketCount(8192));

        assert_eq!(buf.prepare_loss_list(start, mean_rtt), None);

        let now = start;
        assert_eq!(
            buf.push_packet(
                now,
                DataPacket {
                    seq_number: init_seq_num,
                    message_loc: PacketLocation::FIRST,
                    payload: b"hello"[..].into(),
                    ..basic_pack()
                }
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(
            buf.push_packet(
                now,
                DataPacket {
                    seq_number: init_seq_num + 5,
                    message_loc: PacketLocation::LAST,
                    payload: b"yas"[..].into(),
                    ..basic_pack()
                },
            ),
            Ok(ReceivedWithLoss(
                (init_seq_num + 1..init_seq_num + 5).into()
            ))
        );
        assert_eq!(buf.prepare_loss_list(now, mean_rtt), None);

        let now = now + mean_rtt;
        assert_eq!(
            buf.push_packet(
                now,
                DataPacket {
                    seq_number: init_seq_num + 15,
                    message_loc: PacketLocation::LAST,
                    payload: b"nas"[..].into(),
                    ..basic_pack()
                }
            ),
            Ok(ReceivedWithLoss(
                (init_seq_num + 6..init_seq_num + 15).into()
            ))
        );
        assert_eq!(buf.prepare_loss_list(now, mean_rtt), None);

        let now = now + mean_rtt * 3;
        assert_eq!(
            buf.prepare_loss_list(now, mean_rtt),
            Some((1..5).chain(6..15).map(|a| init_seq_num + a).collect())
        );
        assert_eq!(buf.prepare_loss_list(now, mean_rtt), None);
    }

    #[test]
    fn drop_too_late_packets() {
        // packets:
        //  (0) missing
        //  (1) late
        //  (0) missing
        //  (2) on time

        let _ = pretty_env_logger::try_init();

        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(0);

        let mut buf = ReceiveBuffer::new(start, tsbpd, true, init_seq_num, PacketCount(8192));

        let now = start;
        let _ = buf.push_packet(
            now,
            DataPacket {
                seq_number: init_seq_num + 1,
                message_loc: PacketLocation::FIRST,
                ..basic_pack()
            },
        );
        assert_eq!(buf.pop_next_message(now), Ok(None));
        assert_eq!(buf.next_ack_dsn(), init_seq_num);

        let now = now + tsbpd;
        let _ = buf.push_packet(
            now,
            DataPacket {
                timestamp: TimeStamp::MIN + tsbpd,
                seq_number: init_seq_num + 3,
                payload: b"test"[..].into(),
                ..basic_pack()
            },
        );
        assert_eq!(buf.pop_next_message(now), Ok(None));
        assert_eq!(buf.next_ack_dsn(), init_seq_num);

        // 5 ms buffer release tolerance, we are ok with releasing them 5ms late
        let now = now + Duration::from_millis(5);
        // it should drop all packets before and including the last late packet
        assert_eq!(
            buf.pop_next_message(now),
            Err(MessageError {
                too_late_packets: SeqNumber(0)..SeqNumber(2),
                delay: TimeSpan::from_millis(5)
            })
        );
        assert_eq!(buf.next_ack_dsn(), SeqNumber(2));

        // it should continue to wait for any remaining missing packets
        assert_eq!(buf.pop_next_message(now), Ok(None));
        assert_eq!(buf.next_ack_dsn(), SeqNumber(2));
    }

    #[test]
    fn not_dropping_too_late_packets() {
        let _ = pretty_env_logger::try_init();

        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, false, init_seq_num, PacketCount(8192));

        let now = start;
        let _ = buf.push_packet(
            now,
            DataPacket {
                seq_number: init_seq_num + 1,
                message_loc: PacketLocation::FIRST,
                payload: b"hello"[..].into(),
                ..basic_pack()
            },
        );
        let _ = buf.push_packet(
            now,
            DataPacket {
                seq_number: init_seq_num + 2,
                message_loc: PacketLocation::MIDDLE,
                payload: b"hello"[..].into(),
                ..basic_pack()
            },
        );
        assert_eq!(buf.pop_next_message(now), Ok(None));
        assert_eq!(buf.next_ack_dsn(), init_seq_num);

        let now = now + tsbpd;
        let _ = buf.push_packet(
            now,
            DataPacket {
                timestamp: TimeStamp::MIN + tsbpd,
                seq_number: init_seq_num + 5,
                message_loc: PacketLocation::ONLY,
                payload: b"yas"[..].into(),
                ..basic_pack()
            },
        );
        assert_eq!(buf.pop_next_message(now), Ok(None));
        assert_eq!(buf.next_ack_dsn(), init_seq_num);

        // 2 ms buffer release tolerance, we are ok with releasing them 2ms late
        let now = now + Duration::from_millis(5);
        // it should not drop packets
        assert_eq!(buf.pop_next_message(now), Ok(None));
        assert_eq!(buf.next_ack_dsn(), init_seq_num, "{buf:?}");

        // 2 ms buffer release tolerance, we are ok with releasing them 2ms late
        let now = now + tsbpd + Duration::from_millis(5);
        // it should not drop packets
        assert_eq!(buf.pop_next_message(now), Ok(None));
        assert_eq!(buf.next_ack_dsn(), init_seq_num);

        assert_eq!(buf.pop_next_message(now), Ok(None));
        assert_eq!(buf.next_ack_dsn(), init_seq_num);
    }

    #[test]
    fn drop_message() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);
        let mean_rtt = TimeSpan::from_micros(10_000);

        let mut buf = ReceiveBuffer::new(start, tsbpd, true, init_seq_num, PacketCount(8192));

        let now = start;
        assert_eq!(
            buf.push_packet(
                now,
                DataPacket {
                    seq_number: init_seq_num + 3,
                    message_loc: PacketLocation::LAST,
                    payload: b"yas"[..].into(),
                    ..basic_pack()
                },
            ),
            Ok(ReceivedWithLoss((init_seq_num..init_seq_num + 3).into()))
        );

        // fully out of bounds
        assert_eq!(buf.drop_packets(init_seq_num + 9..init_seq_num + 12), 0);

        // a range that wraps around the maximum sequence number
        assert_eq!(
            buf.drop_packets(SeqNumber(SeqNumber::MAX - 2)..SeqNumber(3)),
            0
        );

        // only drop packets that are marked Lost, i.e. pending NAK
        assert_eq!(buf.drop_packets(init_seq_num - 1..init_seq_num + 5), 3);

        // no longer schedule the dropped packets for NAK
        let now = now + mean_rtt * 3;
        assert_eq!(buf.prepare_loss_list(now, mean_rtt), None);
    }

    #[test]
    fn buffer_sizing() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, true, init_seq_num, PacketCount(10));

        assert_eq!(buf.buffer_available(), 10);

        // in order, no overrun
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num,
                    ..basic_pack()
                },
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(buf.buffer_available(), 9);

        // normal, no overrun
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 8,
                    ..basic_pack()
                },
            ),
            Ok(ReceivedWithLoss(
                (init_seq_num + 1..init_seq_num + 8).into()
            ))
        );
        assert_eq!(buf.buffer_available(), 1);

        // past end, overrun
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 10,
                    ..basic_pack()
                },
            ),
            Err(PacketTooEarly {
                seq_number: init_seq_num + 10,
                buffer_available: 1,
                buffer_required: 2
            })
        );
        assert_eq!(buf.buffer_available(), 1);

        // normal, no overrun
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 9,
                    ..basic_pack()
                },
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(buf.buffer_available(), 0);

        // past end, overrun
        assert_eq!(
            buf.push_packet(
                start,
                DataPacket {
                    seq_number: init_seq_num + 10,
                    ..basic_pack()
                },
            ),
            Err(BufferFull {
                seq_number: init_seq_num + 10,
                buffer_size: 10
            })
        );
        assert_eq!(buf.buffer_available(), 0);

        // make room for last packetx
        buf.pop_next_message(start + tsbpd).unwrap();
        assert_eq!(buf.buffer_available(), 1);

        // should work this time
        assert_eq!(
            buf.push_packet(
                start + tsbpd,
                DataPacket {
                    seq_number: init_seq_num + 10,
                    ..basic_pack()
                },
            ),
            Ok(Received {
                lrsn: init_seq_num + 1,
                recovered: false
            })
        );
        assert_eq!(buf.buffer_available(), 0);
    }

    #[test]
    fn rx_acknowledged_time() {
        let tsbpd = Duration::from_secs(2);
        let start = Instant::now();
        let init_seq_num = SeqNumber(5);

        let mut buf = ReceiveBuffer::new(start, tsbpd, true, init_seq_num, PacketCount(10));

        let add_packet = |i, buf: &mut ReceiveBuffer| {
            buf.push_packet(
                start + Duration::from_micros(u64::from(i) * 10),
                DataPacket {
                    seq_number: init_seq_num + i,
                    timestamp: TimeStamp::from_micros(i * 10),
                    ..basic_pack()
                },
            )
            .unwrap();
        };

        assert_eq!(buf.rx_acknowledged_time(), Duration::from_secs(0));

        add_packet(0, &mut buf);
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_secs(0));

        // in order, increases rx_acknowledged_time
        add_packet(1, &mut buf);
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_micros(10));

        // out of order, no change
        add_packet(3, &mut buf);
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_micros(10));

        // got missing paket, goes up
        add_packet(2, &mut buf);
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_micros(30));

        // pop packets
        buf.pop_next_message(start + tsbpd + Duration::from_micros(10))
            .unwrap()
            .unwrap();
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_micros(20));

        buf.pop_next_message(start + tsbpd + Duration::from_micros(20))
            .unwrap()
            .unwrap();
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_micros(10));

        buf.pop_next_message(start + tsbpd + Duration::from_micros(30))
            .unwrap()
            .unwrap();
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_micros(0));

        buf.pop_next_message(start + tsbpd + Duration::from_micros(40))
            .unwrap()
            .unwrap();
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_micros(0));

        assert_eq!(
            buf.pop_next_message(start + tsbpd + Duration::from_micros(40))
                .unwrap(),
            None
        );
        assert_eq!(buf.rx_acknowledged_time(), Duration::from_micros(0));
    }

    mod reorder_tolerance {
        use pretty_assertions::assert_eq;

        use super::*;

        fn buffer(max: u64) -> (ReceiveBuffer, Instant) {
            let start = Instant::now();
            let buf = ReceiveBuffer::new(
                start,
                Duration::from_secs(2),
                true,
                SeqNumber(0),
                PacketCount(8192),
            )
            .with_reorder_tolerance_max(PacketCount(max));
            (buf, start)
        }

        fn push(
            buf: &mut ReceiveBuffer,
            now: Instant,
            seq: u32,
            retransmitted: bool,
        ) -> Option<Vec<u32>> {
            let data = DataPacket {
                seq_number: SeqNumber(seq),
                retransmitted,
                ..basic_pack()
            };
            match buf.push_packet(now, data).unwrap() {
                ReceivedWithLoss(list) => {
                    Some(list.into_iter_decompressed().map(|s| s.as_raw()).collect())
                }
                _ => None,
            }
        }

        /// Packets 0, 2, 1: the gap at 1 is reported at once, then turns out
        /// to be reordering, so the tolerance becomes 1. Next expected: 3.
        fn taught_one(max: u64) -> (ReceiveBuffer, Instant) {
            let (mut buf, now) = buffer(max);
            assert_eq!(push(&mut buf, now, 0, false), None);
            assert_eq!(push(&mut buf, now, 2, false), Some(vec![1]));
            assert_eq!(push(&mut buf, now, 1, false), None);
            (buf, now)
        }

        #[test]
        fn off_reports_every_gap_at_once() {
            let (mut buf, now) = taught_one(0);
            assert_eq!(push(&mut buf, now, 3, false), None);
            assert_eq!(push(&mut buf, now, 5, false), Some(vec![4]));
        }

        #[test]
        fn a_reordered_packet_is_never_reported() {
            let (mut buf, now) = taught_one(200);
            assert_eq!(push(&mut buf, now, 3, false), None);
            assert_eq!(
                push(&mut buf, now, 5, false),
                None,
                "the gap at 4 waits out the tolerance"
            );
            assert_eq!(push(&mut buf, now, 4, false), None);
            assert_eq!(push(&mut buf, now, 6, false), None);
            assert!(buf
                .prepare_loss_list(now + Duration::from_secs(10), TimeSpan::from_micros(1000))
                .is_none());
        }

        #[test]
        fn real_loss_is_reported_when_the_tolerance_runs_out() {
            let (mut buf, now) = taught_one(200);
            assert_eq!(push(&mut buf, now, 3, false), None);
            assert_eq!(push(&mut buf, now, 5, false), None);
            assert_eq!(
                push(&mut buf, now, 6, false),
                Some(vec![4]),
                "one packet followed the gap"
            );
        }

        #[test]
        fn a_packet_that_opens_a_gap_also_reports_an_older_one() {
            let (mut buf, now) = taught_one(200);
            assert_eq!(push(&mut buf, now, 4, false), None); // gap at 3, until 5
            assert_eq!(push(&mut buf, now, 6, false), Some(vec![3])); // 3 is out of tolerance; new gap at 5, until 7
            assert_eq!(push(&mut buf, now, 8, false), Some(vec![5])); // 5 is out; new gap at 7, until 9
        }

        #[test]
        fn tolerance_stops_at_the_maximum() {
            let (mut buf, now) = buffer(3);
            assert_eq!(push(&mut buf, now, 0, false), None);
            assert_eq!(push(&mut buf, now, 10, false), Some((1..10).collect()));
            assert_eq!(push(&mut buf, now, 1, false), None); // 9 packets late, capped at 3
            assert_eq!(push(&mut buf, now, 11, false), None);
            assert_eq!(push(&mut buf, now, 13, false), None); // gap at 12, until 16
            assert_eq!(push(&mut buf, now, 14, false), None);
            assert_eq!(push(&mut buf, now, 15, false), None);
            assert_eq!(push(&mut buf, now, 16, false), Some(vec![12]));
        }

        #[test]
        fn a_retransmission_teaches_nothing() {
            let (mut buf, now) = buffer(200);
            assert_eq!(push(&mut buf, now, 0, false), None);
            assert_eq!(push(&mut buf, now, 2, false), Some(vec![1]));
            assert_eq!(push(&mut buf, now, 1, true), None);
            assert_eq!(push(&mut buf, now, 3, false), None);
            assert_eq!(push(&mut buf, now, 5, false), Some(vec![4]));
        }

        #[test]
        fn the_tolerance_shrinks_while_the_stream_is_in_order() {
            let (mut buf, now) = taught_one(200);
            for seq in 3..53 {
                assert_eq!(push(&mut buf, now, seq, false), None);
            }
            assert_eq!(
                push(&mut buf, now, 54, false),
                Some(vec![53]),
                "50 in-order packets cost one step"
            );
        }

        #[test]
        fn the_timer_reports_a_gap_that_is_still_waiting() {
            let (mut buf, now) = taught_one(200);
            assert_eq!(push(&mut buf, now, 3, false), None);
            assert_eq!(push(&mut buf, now, 5, false), None); // gap at 4; no more packets follow
            let list = buf
                .prepare_loss_list(now + Duration::from_secs(1), TimeSpan::from_micros(1000))
                .unwrap();
            assert_eq!(
                list.into_iter_decompressed()
                    .map(|s| s.as_raw())
                    .collect::<Vec<_>>(),
                vec![4]
            );
            assert_eq!(
                push(&mut buf, now, 6, false),
                None,
                "already reported, so not again"
            );
        }
    }
}
