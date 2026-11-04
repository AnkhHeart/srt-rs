mod input;
mod session;
mod statistics;

use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::Debug,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::Duration,
    time::Instant,
};

use crate::{packet::*, protocol::time::Timer, settings::ConnInitSettings};

use session::*;

pub use input::*;
pub use statistics::*;

#[derive(Clone, Debug)]
pub struct ListenerSettings {}

/// How long a session that has not been opened may go without a packet before it is discarded
const PENDING_SESSION_TIMEOUT: Duration = Duration::from_secs(5);

/// The most sessions that have not been opened, in total
const MAX_PENDING_SESSIONS: usize = 4096;

/// The most sessions that have not been opened for a single remote IP address, where all
/// IPv6 addresses in the same /64 prefix count as one address.
/// Loopback addresses are exempt, as a local relay may forward many callers from one address.
const MAX_PENDING_SESSIONS_PER_IP: usize = 16;

#[derive(Debug)]
struct Session {
    state: SessionState,
    last_activity: Instant,
    /// Whether the session counts against the limits on sessions that are not open
    pending: bool,
}

/// Tracks the sessions that are not yet open
#[derive(Debug, Default)]
struct PendingCount {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

impl PendingCount {
    /// The address that the per-IP limit is counted against, or `None` for loopback.
    /// IPv4 addresses are counted individually, IPv6 addresses by their /64 prefix.
    fn limit_key(ip: IpAddr) -> Option<IpAddr> {
        match ip.to_canonical() {
            ip if ip.is_loopback() => None,
            IpAddr::V6(ip) => Some(IpAddr::V6(Ipv6Addr::from(
                u128::from(ip) & !u128::from(u64::MAX),
            ))),
            ip => Some(ip),
        }
    }

    fn try_add(&mut self, ip: IpAddr) -> bool {
        let Some(key) = Self::limit_key(ip) else {
            if self.total >= MAX_PENDING_SESSIONS {
                return false;
            }
            self.total += 1;
            return true;
        };
        let count = self.per_ip.entry(key).or_default();
        if self.total >= MAX_PENDING_SESSIONS || *count >= MAX_PENDING_SESSIONS_PER_IP {
            if *count == 0 {
                self.per_ip.remove(&key);
            }
            return false;
        }
        *count += 1;
        self.total += 1;
        true
    }

    fn release(&mut self, ip: IpAddr) {
        self.total = self.total.saturating_sub(1);
        let Some(key) = Self::limit_key(ip) else {
            return;
        };
        if let Entry::Occupied(mut count) = self.per_ip.entry(key) {
            *count.get_mut() -= 1;
            if *count.get() == 0 {
                count.remove();
            }
        }
    }
}

#[derive(Debug)]
pub struct MultiplexListener {
    start_time: Instant,
    local_address: SocketAddr,
    settings: ConnInitSettings,
    sessions: HashMap<SessionId, Session>,
    pending: PendingCount,
    stats: ListenerStatistics,
    stats_timer: Timer,
}

impl MultiplexListener {
    pub fn new(now: Instant, local_address: SocketAddr, settings: ConnInitSettings) -> Self {
        Self {
            start_time: now,
            local_address,
            settings,
            sessions: Default::default(),
            pending: Default::default(),
            stats: Default::default(),
            stats_timer: Timer::new(now, Duration::from_secs(1)),
        }
    }

    pub fn handle_input(&mut self, now: Instant, input: Input) -> Action {
        match input {
            Input::Packet(packet) => self.handle_input_packet(now, packet),
            Input::AccessResponse(response) => self.handle_input_access_response(now, response),
            Input::Timer => self.handle_timer(now),
            Input::Success(result_of) => self.handle_success(now, result_of),
            Input::Failure(result_of) => self.handle_failure(now, result_of),
        }
    }

    fn handle_input_packet(&mut self, now: Instant, packet: ReceivePacketResult) -> Action {
        match packet {
            Ok(packet) => self.handle_packet(now, packet),
            Err(error) => self.handle_packet_receive_error(now, error),
        }
    }

    fn handle_input_access_response(
        &mut self,
        now: Instant,
        response: Option<(SessionId, AccessControlResponse)>,
    ) -> Action {
        match response {
            Some((session_id, response)) => {
                self.handle_access_control_response(now, session_id, response)
            }
            None => self.handle_close(),
        }
    }

    fn handle_packet(&mut self, now: Instant, packet: (Packet, SocketAddr)) -> Action {
        self.stats.rx_packets += 1;
        //self.stats.rx_bytes += packet
        let session_id = SessionId(packet.1);
        let session = match self.sessions.entry(session_id) {
            Entry::Occupied(session) => session.into_mut(),
            Entry::Vacant(session) => {
                if !self.pending.try_add(packet.1.ip()) {
                    // too many sessions are waiting to be opened, ignore the packet
                    return Action::WaitForInput;
                }
                session.insert(Session {
                    state: SessionState::new_pending(self.settings.copy_randomize()),
                    last_activity: now,
                    pending: true,
                })
            }
        };
        session.last_activity = now;
        let action = session.state.handle_packet(now, session_id, packet);
        self.update_pending(&session_id);
        action
    }

    /// Stops counting a session against the pending limits once it is open
    fn update_pending(&mut self, session_id: &SessionId) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            if session.pending && session.state.is_open() {
                session.pending = false;
                self.pending.release(session_id.0.ip());
            }
        }
    }

    fn remove_session(&mut self, session_id: &SessionId) {
        if let Some(session) = self.sessions.remove(session_id) {
            if session.pending {
                self.pending.release(session_id.0.ip());
            }
        }
    }

    /// Discards sessions that have gone quiet. Sessions that hold resources outside of the
    /// listener are returned, one at a time, so that the I/O loop can release them.
    fn expire_sessions(&mut self, now: Instant) -> Option<SessionId> {
        // a connection that is open closes itself after the peer idle timeout
        let open_timeout = self.settings.peer_idle_timeout.saturating_mul(2);
        let expired: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|(_, session)| {
                let timeout = if session.state.is_open() {
                    open_timeout
                } else {
                    PENDING_SESSION_TIMEOUT
                };
                now.duration_since(session.last_activity) > timeout
            })
            .map(|(session_id, _)| *session_id)
            .collect();

        let mut to_drop = None;
        for session_id in expired {
            let holds_resources = self.sessions.get(&session_id).is_some_and(|session| {
                session.state.is_open() || session.state.is_awaiting_access()
            });
            if holds_resources && to_drop.is_some() {
                continue;
            }
            self.remove_session(&session_id);
            if holds_resources {
                to_drop = Some(session_id);
            }
        }
        to_drop
    }

    fn handle_packet_receive_error(&mut self, now: Instant, error: ReceivePacketError) -> Action {
        self.warn(now, "packet", &error);

        use ReceivePacketError::*;
        match error {
            Parse(_) => self.stats.rx_parse_errors += 1,
            Io(_) => self.stats.rx_io_errors += 1,
        }

        Action::WaitForInput
    }

    fn handle_access_control_response(
        &mut self,
        now: Instant,
        session_id: SessionId,
        response: AccessControlResponse,
    ) -> Action {
        match self.sessions.get_mut(&session_id) {
            Some(session) => {
                session.last_activity = now;
                let action = session
                    .state
                    .handle_access_control_response(now, session_id, response);
                self.update_pending(&session_id);
                action
            }
            None => Action::DropConnection(session_id),
        }
    }

    fn handle_timer(&mut self, now: Instant) -> Action {
        if let Some(session_id) = self.expire_sessions(now) {
            Action::DropConnection(session_id)
        } else if self.stats_timer.check_expired(now).is_some() {
            Action::UpdateStatistics(&self.stats)
        } else {
            // TODO: create an action that returns an action with an Iterator that ticks time forward
            //  for all the sessions, yielding the results to the I/O loop
            Action::WaitForInput
        }
    }

    fn handle_success(&mut self, _now: Instant, result_of: ResultOf) -> Action {
        use ResultOf::*;
        match result_of {
            SendPacket(_) => {
                self.stats.tx_packets += 1;
            }
            RequestAccess(_) => {
                self.stats.cx_inbound += 1;
            }
            RejectConnection(session_id) => {
                self.stats.cx_rejected += 1;
                self.remove_session(&session_id);
            }
            OpenConnection(_) => {
                self.stats.cx_opened += 1;
            }
            DelegatePacket(_) => {
                self.stats.delegated_packets += 1;
            }
            DropConnection(session_id) => {
                self.stats.cx_dropped += 1;
                self.remove_session(&session_id);
            }
            UpdateStatistics => {}
        }
        Action::WaitForInput
    }

    fn handle_failure(&mut self, now: Instant, result_of: ResultOf) -> Action {
        self.warn(now, "failure", &result_of);

        use ResultOf::*;
        match result_of {
            DelegatePacket(session_id) => Action::DropConnection(session_id),
            // TODO: stats? anything else?
            _ => Action::WaitForInput,
        }
    }

    fn handle_close(&mut self) -> Action {
        Action::Close
    }

    fn warn(&self, now: Instant, tag: &str, debug: &impl Debug) {
        log::warn!(
            "{:?}|listen:{}|{} - {:?}",
            TimeSpan::from_interval(self.start_time, now),
            self.local_address.port(),
            tag,
            debug
        );
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    use rand::random;

    use crate::options::{KeySize, PacketCount, PacketSize, SrtVersion};

    use super::*;

    fn conn_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8765)
    }

    fn test_induction() -> HandshakeControlInfo {
        HandshakeControlInfo {
            init_seq_num: random(),
            max_packet_size: PacketSize(1316),
            max_flow_size: PacketCount(256_000),
            shake_type: ShakeType::Induction,
            socket_id: SocketId(15),
            syn_cookie: 0,
            peer_addr: IpAddr::from([127, 0, 0, 1]),
            info: HandshakeVsInfo::V5(HsV5Info::default()),
        }
    }

    fn test_conclusion() -> HandshakeControlInfo {
        HandshakeControlInfo {
            init_seq_num: random(),
            max_packet_size: PacketSize(1316),
            max_flow_size: PacketCount(256_000),
            shake_type: ShakeType::Conclusion,
            socket_id: SocketId(15),
            syn_cookie: crate::protocol::pending_connection::cookie::gen_cookie(&conn_addr()),
            peer_addr: IpAddr::from([127, 0, 0, 1]),
            info: HandshakeVsInfo::V5(HsV5Info {
                key_size: KeySize::Unspecified,
                ext_hs: Some(SrtControlPacket::HandshakeRequest(SrtHandshake {
                    version: SrtVersion::CURRENT,
                    flags: SrtShakeFlags::SUPPORTED,
                    send_latency: Duration::from_secs(1),
                    recv_latency: Duration::from_secs(2),
                })),
                ext_km: None,
                ext_group: None,
                sid: None,
            }),
        }
    }

    fn dest_sock_id() -> SocketId {
        SocketId(6)
    }

    fn session_id() -> SessionId {
        SessionId(conn_addr())
    }

    fn build_hs_pack(i: HandshakeControlInfo) -> Packet {
        Packet::Control(ControlPacket {
            timestamp: TimeStamp::from_micros(0),
            dest_sockid: dest_sock_id(),
            control_type: ControlTypes::Handshake(i),
        })
    }

    #[test]
    fn connect() {
        let settings = ConnInitSettings::default();
        let local = "0.0.0.0:2000".parse().unwrap();
        let mut listener = MultiplexListener::new(Instant::now(), local, settings);

        let packet = build_hs_pack(test_induction());
        let action =
            listener.handle_input(Instant::now(), Input::Packet(Ok((packet, conn_addr()))));
        assert_matches!(action, Action::SendPacket(_));

        let packet = build_hs_pack(test_conclusion());
        let action =
            listener.handle_input(Instant::now(), Input::Packet(Ok((packet, conn_addr()))));
        assert_matches!(action, Action::RequestAccess(_, _));

        let action = listener.handle_input(
            Instant::now(),
            Input::AccessResponse(Some((session_id(), AccessControlResponse::Accepted(None)))),
        );
        assert_matches!(action, Action::OpenConnection(_, _));

        use crate::listener::ResultOf::*;

        let action =
            listener.handle_input(Instant::now(), Input::Success(OpenConnection(session_id())));
        assert_matches!(action, Action::WaitForInput);

        let packet = build_hs_pack(test_conclusion());
        let action =
            listener.handle_input(Instant::now(), Input::Packet(Ok((packet, conn_addr()))));
        assert_matches!(action, Action::DelegatePacket(_, _));
    }

    #[test]
    fn sessions_get_distinct_local_socket_ids() {
        let settings = ConnInitSettings::default();
        let local = "0.0.0.0:2000".parse().unwrap();
        let mut listener = MultiplexListener::new(Instant::now(), local, settings);

        let addrs: Vec<SocketAddr> = (0..2)
            .map(|i| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8765 + i))
            .collect();
        for addr in &addrs {
            let packet = build_hs_pack(test_induction());
            listener.handle_input(Instant::now(), Input::Packet(Ok((packet, *addr))));
        }

        let ids: Vec<_> = addrs
            .iter()
            .map(|addr| match &listener.sessions[&SessionId(*addr)].state {
                SessionState::Pending(listen) => listen.settings().local_sockid,
                state => panic!("unexpected session state {state:?}"),
            })
            .collect();
        assert_ne!(ids[0], ids[1]);
    }

    fn new_listener(now: Instant) -> MultiplexListener {
        let local = "0.0.0.0:2000".parse().unwrap();
        MultiplexListener::new(now, local, ConnInitSettings::default())
    }

    fn induct(listener: &mut MultiplexListener, now: Instant, addr: SocketAddr) -> Action {
        let packet = build_hs_pack(test_induction());
        listener.handle_input(now, Input::Packet(Ok((packet, addr))))
    }

    fn addr_n(n: usize) -> SocketAddr {
        let n = n as u32;
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n)), 8765)
    }

    #[test]
    fn pending_sessions_expire() {
        let start = Instant::now();
        let mut listener = new_listener(start);

        for n in 0..100 {
            assert_matches!(
                induct(&mut listener, start, addr_n(n)),
                Action::SendPacket(_)
            );
        }
        assert_eq!(listener.sessions.len(), 100);
        assert_eq!(listener.pending.total, 100);

        // still within the timeout
        listener.handle_input(start + Duration::from_secs(4), Input::Timer);
        assert_eq!(listener.sessions.len(), 100);

        // a session that sees activity is kept
        induct(&mut listener, start + Duration::from_secs(4), addr_n(0));

        listener.handle_input(start + Duration::from_secs(6), Input::Timer);
        assert_eq!(listener.sessions.len(), 1);
        assert_eq!(listener.pending.total, 1);

        listener.handle_input(start + Duration::from_secs(10), Input::Timer);
        assert!(listener.sessions.is_empty());
        assert_eq!(listener.pending.total, 0);
        assert!(listener.pending.per_ip.is_empty());
    }

    #[test]
    fn pending_sessions_are_limited_per_ip() {
        let start = Instant::now();
        let mut listener = new_listener(start);

        for port in 0..MAX_PENDING_SESSIONS_PER_IP + 10 {
            let addr = SocketAddr::new(addr_n(0).ip(), 2000 + port as u16);
            induct(&mut listener, start, addr);
        }
        assert_eq!(listener.sessions.len(), MAX_PENDING_SESSIONS_PER_IP);

        // other addresses are not affected
        assert_matches!(
            induct(&mut listener, start, addr_n(1)),
            Action::SendPacket(_)
        );
        assert_eq!(listener.sessions.len(), MAX_PENDING_SESSIONS_PER_IP + 1);
    }

    fn v6_addr(prefix: u16, host: u16) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, prefix, 0, 0, 0, host)),
            8765,
        )
    }

    #[test]
    fn pending_sessions_are_limited_per_ipv6_prefix() {
        let start = Instant::now();
        let mut listener = new_listener(start);

        // different addresses in the same /64 share one limit
        for host in 0..MAX_PENDING_SESSIONS_PER_IP + 1 {
            induct(&mut listener, start, v6_addr(1, host as u16 + 1));
        }
        assert_eq!(listener.sessions.len(), MAX_PENDING_SESSIONS_PER_IP);
        assert_eq!(listener.pending.per_ip.len(), 1);

        // other prefixes, and IPv4 addresses, are not affected
        assert_matches!(
            induct(&mut listener, start, v6_addr(2, 1)),
            Action::SendPacket(_)
        );
        assert_matches!(
            induct(&mut listener, start, addr_n(0)),
            Action::SendPacket(_)
        );
        assert_eq!(listener.sessions.len(), MAX_PENDING_SESSIONS_PER_IP + 2);
        assert_eq!(listener.pending.per_ip.len(), 3);

        // expiring the sessions frees the prefix
        listener.handle_input(start + Duration::from_secs(6), Input::Timer);
        assert!(listener.sessions.is_empty());
        assert_eq!(listener.pending.total, 0);
        assert!(listener.pending.per_ip.is_empty());
        assert_matches!(
            induct(
                &mut listener,
                start + Duration::from_secs(6),
                v6_addr(1, 99)
            ),
            Action::SendPacket(_)
        );
    }

    #[test]
    fn pending_release_frees_ipv6_prefix_slot() {
        let mut pending = PendingCount::default();
        let a = v6_addr(1, 1).ip();
        let b = v6_addr(1, 2).ip();

        for _ in 0..MAX_PENDING_SESSIONS_PER_IP {
            assert!(pending.try_add(a));
        }
        assert!(!pending.try_add(b));

        pending.release(b);
        assert!(pending.try_add(a));
        assert!(!pending.try_add(a));
    }

    #[test]
    fn pending_ipv4_mapped_counts_as_ipv4() {
        let mut pending = PendingCount::default();
        let v4 = addr_n(0).ip();
        let IpAddr::V4(v4_addr) = v4 else {
            unreachable!()
        };
        let mapped = IpAddr::V6(v4_addr.to_ipv6_mapped());

        for _ in 0..MAX_PENDING_SESSIONS_PER_IP {
            assert!(pending.try_add(mapped));
        }
        assert!(!pending.try_add(v4));
        // a different IPv4 address in the same /24 is counted separately
        assert!(pending.try_add(addr_n(1).ip()));

        pending.release(v4);
        assert!(pending.try_add(mapped));
    }

    #[test]
    fn loopback_sessions_are_not_limited_per_ip() {
        let start = Instant::now();
        let mut listener = new_listener(start);

        let loopbacks = [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
        ];
        for (n, ip) in loopbacks.iter().enumerate() {
            for port in 0..MAX_PENDING_SESSIONS_PER_IP + 10 {
                let addr = SocketAddr::new(*ip, 2000 + port as u16);
                assert_matches!(induct(&mut listener, start, addr), Action::SendPacket(_));
            }
            assert_eq!(
                listener.sessions.len(),
                (n + 1) * (MAX_PENDING_SESSIONS_PER_IP + 10)
            );
        }
        assert!(listener.pending.per_ip.is_empty());

        // other addresses are still limited
        for port in 0..MAX_PENDING_SESSIONS_PER_IP + 10 {
            let addr = SocketAddr::new(addr_n(0).ip(), 2000 + port as u16);
            induct(&mut listener, start, addr);
        }
        assert_eq!(
            listener.sessions.len(),
            loopbacks.len() * (MAX_PENDING_SESSIONS_PER_IP + 10) + MAX_PENDING_SESSIONS_PER_IP
        );

        // pending loopback sessions are released when they expire
        listener.handle_input(start + Duration::from_secs(6), Input::Timer);
        assert!(listener.sessions.is_empty());
        assert_eq!(listener.pending.total, 0);
    }

    #[test]
    fn loopback_sessions_are_limited_in_total() {
        let start = Instant::now();
        let mut listener = new_listener(start);

        for n in 0..MAX_PENDING_SESSIONS + 10 {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1024 + n as u16);
            induct(&mut listener, start, addr);
        }
        assert_eq!(listener.sessions.len(), MAX_PENDING_SESSIONS);
        assert_eq!(listener.pending.total, MAX_PENDING_SESSIONS);
    }

    #[test]
    fn pending_sessions_are_limited_in_total() {
        let start = Instant::now();
        let mut listener = new_listener(start);

        for n in 0..MAX_PENDING_SESSIONS + 10 {
            induct(&mut listener, start, addr_n(n));
        }
        assert_eq!(listener.sessions.len(), MAX_PENDING_SESSIONS);

        // room is made once sessions expire
        listener.handle_input(start + Duration::from_secs(6), Input::Timer);
        assert!(listener.sessions.is_empty());
        assert_matches!(
            induct(&mut listener, start + Duration::from_secs(6), addr_n(0)),
            Action::SendPacket(_)
        );
    }

    #[test]
    fn open_sessions_are_not_pending_and_expire_when_idle() {
        let start = Instant::now();
        let mut listener = new_listener(start);

        induct(&mut listener, start, conn_addr());
        let packet = build_hs_pack(test_conclusion());
        let action = listener.handle_input(start, Input::Packet(Ok((packet, conn_addr()))));
        assert_matches!(action, Action::RequestAccess(_, _));

        // a request waiting on the application is released after the timeout
        let action = listener.handle_input(start + Duration::from_secs(6), Input::Timer);
        assert_eq!(action, Action::DropConnection(session_id()));
        assert!(listener.sessions.is_empty());
        assert_eq!(listener.pending.total, 0);

        induct(&mut listener, start, conn_addr());
        let packet = build_hs_pack(test_conclusion());
        listener.handle_input(start, Input::Packet(Ok((packet, conn_addr()))));
        let action = listener.handle_input(
            start,
            Input::AccessResponse(Some((session_id(), AccessControlResponse::Accepted(None)))),
        );
        assert_matches!(action, Action::OpenConnection(_, _));
        assert_eq!(listener.pending.total, 0);
        assert_eq!(listener.sessions.len(), 1);

        // a late response for an open session is ignored
        let action = listener.handle_input(
            start,
            Input::AccessResponse(Some((session_id(), AccessControlResponse::Dropped))),
        );
        assert_eq!(action, Action::WaitForInput);

        // an open session is kept while the connection is alive, then released
        let idle = listener.settings.peer_idle_timeout;
        let action = listener.handle_input(start + idle, Input::Timer);
        assert_ne!(action, Action::DropConnection(session_id()));
        assert_eq!(listener.sessions.len(), 1);

        let action = listener.handle_input(start + idle * 3, Input::Timer);
        assert_eq!(action, Action::DropConnection(session_id()));
        assert!(listener.sessions.is_empty());
    }

    #[test]
    fn reject() {
        let settings = ConnInitSettings::default();
        let local = "127.0.0.1:2000".parse().unwrap();
        let mut listener = MultiplexListener::new(Instant::now(), local, settings);

        let packet = build_hs_pack(test_induction());
        let action =
            listener.handle_input(Instant::now(), Input::Packet(Ok((packet, conn_addr()))));
        assert_matches!(action, Action::SendPacket(_));

        let packet = build_hs_pack(test_conclusion());
        let action =
            listener.handle_input(Instant::now(), Input::Packet(Ok((packet, conn_addr()))));
        assert_matches!(action, Action::RequestAccess(_, _));

        let action = listener.handle_input(
            Instant::now(),
            Input::AccessResponse(Some((
                session_id(),
                AccessControlResponse::Rejected(RejectReason::User(100)),
            ))),
        );
        assert_matches!(
            action,
            Action::RejectConnection(_, Some((Packet::Control(_), _)))
        );

        let packet = build_hs_pack(test_conclusion());
        let action =
            listener.handle_input(Instant::now(), Input::Packet(Ok((packet, conn_addr()))));
        assert_matches!(
            action,
            Action::RejectConnection(_, Some((Packet::Control(_), _)))
        );

        let action = listener.handle_input(
            Instant::now(),
            Input::Success(ResultOf::RejectConnection(session_id())),
        );
        assert_eq!(action, Action::WaitForInput);
    }
}
