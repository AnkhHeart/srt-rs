use std::{io::ErrorKind, net::SocketAddr};

use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use srt_protocol::{
    connection::{Connection, ConnectionSettings},
    listener::*,
    options::*,
    packet::*,
    settings::*,
};
use tokio::task::JoinHandle;

use crate::{
    net::PacketSocket,
    socket::factory::{self, SrtSocketFactory, SrtSocketTaskFactory},
    SrtSocket,
};

#[derive(Debug)]
pub struct ConnectionRequest {
    response_sender: ResponseSender,
    request: AccessControlRequest,
    settings_receiver: oneshot::Receiver<(ConnectionSettings, JoinHandle<()>)>,
    socket_factory: SrtSocketFactory,
}

impl ConnectionRequest {
    pub fn local_socket_id(&self) -> SocketId {
        self.request.local_socket_id
    }
    pub fn remote_socket_id(&self) -> SocketId {
        self.request.remote_socket_id
    }
    pub fn remote(&self) -> SocketAddr {
        self.request.remote
    }
    pub fn stream_id(&self) -> Option<&StreamId> {
        self.request.stream_id.as_ref()
    }
    pub fn key_size(&self) -> KeySize {
        self.request.key_size
    }

    pub async fn accept(
        self,
        key_settings: Option<KeySettings>,
    ) -> Result<SrtSocket, std::io::Error> {
        self.response_sender
            .send(AccessControlResponse::Accepted(key_settings))
            .await?;

        let (settings, jh) = self
            .settings_receiver
            .await
            .map_err(|e| std::io::Error::new(ErrorKind::NotConnected, e))?;

        Ok(self.socket_factory.create_socket(settings, jh))
    }

    pub async fn reject(self, reason: RejectReason) -> Result<(), std::io::Error> {
        self.response_sender
            .send(AccessControlResponse::Rejected(reason))
            .await
    }
}

#[derive(Debug)]
pub struct PendingConnection {
    settings_sender: oneshot::Sender<(ConnectionSettings, JoinHandle<()>)>,
    task_factory: SrtSocketTaskFactory,
}

impl PendingConnection {
    pub fn start_approval(
        session_id: SessionId,
        request: AccessControlRequest,
        response_sender: mpsc::Sender<(SessionId, AccessControlResponse)>,
    ) -> (PendingConnection, ConnectionRequest) {
        let (socket_factory, task_factory) = factory::split_new();

        let (settings_sender, settings_receiver) = oneshot::channel();
        let response_sender = ResponseSender::new(session_id, response_sender);

        let state = PendingConnection {
            settings_sender,
            task_factory,
        };

        let request = ConnectionRequest {
            request,
            response_sender,
            settings_receiver,
            socket_factory,
        };

        (state, request)
    }

    pub fn transition_to_open(
        self,
        socket: &PacketSocket,
        connection: Connection,
    ) -> Result<OpenConnection, ()> {
        let (packet_sender, socket) = socket.clone_channel(100);
        let (handle, settings) = self.task_factory.spawn_task(socket, connection);
        self.settings_sender
            .send((settings, handle))
            .ok()
            .ok_or(())?;
        Ok(OpenConnection { packet_sender })
    }
}

#[derive(Debug)]
pub struct OpenConnection {
    packet_sender: mpsc::Sender<ReceivePacketResult>,
}

impl OpenConnection {
    /// Hands a packet to the connection without waiting. The listener is shared by every
    /// connection, so a connection that is not keeping up must not stall it; its
    /// packets are dropped instead.
    pub async fn send(&mut self, packet: (Packet, SocketAddr)) -> Result<(), ()> {
        match self.packet_sender.try_send(Ok(packet)) {
            Err(e) if e.is_full() => {
                log::debug!("connection queue full, dropping packet");
                Ok(())
            }
            r => r.ok().ok_or(()),
        }
    }

    pub async fn close(&mut self) -> Result<(), ()> {
        self.packet_sender.close().await.ok().ok_or(())
    }
}

#[derive(Debug)]
struct ResponseSender {
    session_id: SessionId,
    sender: mpsc::Sender<(SessionId, AccessControlResponse)>,
    answered: bool,
}

impl ResponseSender {
    fn new(
        session_id: SessionId,
        sender: mpsc::Sender<(SessionId, AccessControlResponse)>,
    ) -> Self {
        Self {
            session_id,
            sender,
            answered: false,
        }
    }

    async fn send(mut self, response: AccessControlResponse) -> Result<(), std::io::Error> {
        let result = self
            .sender
            .send((self.session_id, response))
            .await
            .map_err(|e| std::io::Error::new(ErrorKind::NotConnected, e));
        self.answered = true;
        result
    }
}

impl Drop for ResponseSender {
    fn drop(&mut self) {
        // a request that is dropped without an answer is rejected, so that the caller is not
        // left waiting and the listener can release the pending connection
        if !self.answered {
            let _ = self
                .sender
                .try_send((self.session_id, AccessControlResponse::Dropped));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn send_does_not_block_when_full() {
        let (packet_sender, mut receiver) = mpsc::channel(1);
        let mut connection = OpenConnection { packet_sender };
        let addr: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let packet = Packet::Control(ControlPacket {
            timestamp: TimeStamp::from_micros(0),
            dest_sockid: SocketId(1),
            control_type: ControlTypes::KeepAlive,
        });

        // nothing is reading from the receiver, so the channel fills up
        for _ in 0..10 {
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                connection.send((packet.clone(), addr)),
            )
            .await;
            assert_eq!(result, Ok(Ok(())));
        }

        // a closed channel is still reported
        receiver.close();
        assert_eq!(connection.send((packet, addr)).await, Err(()));
    }
}
