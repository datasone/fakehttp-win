use std::{
    borrow::Cow,
    sync::{Arc, atomic::AtomicBool},
};

use pnet_packet::{
    Packet, ipv4::MutableIpv4Packet, ipv6::MutableIpv6Packet, tcp::MutableTcpPacket,
};
use windivert::{
    WinDivert,
    error::WinDivertError,
    layer::{ForwardLayer, NetworkLayer, WinDivertLayerTrait},
    packet::WinDivertPacket,
};
use windivert_sys::{ChecksumFlags, WINDIVERT_MTU_MAX};

fn fake_payload_http(http_hostname: &str) -> Vec<u8> {
    let payload = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nAccept-Encoding: gzip\r\nAccept-Language: \
         zh-CN\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36\r\n\r\n",
        http_hostname
    );
    payload.as_bytes().to_vec()
}

fn fake_packet<L: WinDivertLayerTrait + 'static>(
    ttl: u8,
    payload: &[u8],
    base_pkt: &WinDivertPacket<L>,
) -> Result<WinDivertPacket<'static, L>, WinDivertError> {
    let mut new_pkt = base_pkt.clone().into_owned();

    let mut pkt_data = new_pkt.data.clone().into_owned();
    pkt_data.resize(pkt_data.len() + payload.len(), 0);

    let new_pkt_data = if base_pkt.address.ipv6() {
        let pkt = MutableIpv6Packet::owned(pkt_data);
        let Some(mut pkt) = pkt else {
            tracing::error!("Invalid IPv6 packet received");
            // We just need an early return here
            return Err(WinDivertError::IOError(std::io::Error::last_os_error()));
        };

        let mut new_payload = pkt.payload().to_vec();
        new_payload.resize(new_payload.len() + payload.len(), 0);
        let tcp_pkt = MutableTcpPacket::owned(new_payload);
        let Some(mut tcp_pkt) = tcp_pkt else {
            tracing::error!("Invalid TCP packet received");
            return Err(WinDivertError::IOError(std::io::Error::last_os_error()));
        };
        let size_shrink = (tcp_pkt.get_data_offset() as usize - 5) * 4;

        tcp_pkt.set_flags(0);
        let source_port = tcp_pkt.get_source();
        let destination_port = tcp_pkt.get_destination();
        tcp_pkt.set_source(destination_port);
        tcp_pkt.set_destination(source_port);
        tcp_pkt.set_sequence(rand::random());
        tcp_pkt.set_acknowledgement(0);
        tcp_pkt.set_data_offset(5);
        tcp_pkt.set_options(&[]);
        tcp_pkt.set_payload(payload);

        let source = pkt.get_source();
        let destination = pkt.get_destination();
        tracing::debug!(
            "{}:{} ====SYN+ACK===> {}:{}",
            source,
            source_port,
            destination,
            destination_port
        );
        tracing::debug!(
            "{}:{} <===FAKEPKT==== {}:{}",
            source,
            source_port,
            destination,
            destination_port
        );

        tcp_pkt.set_checksum(pnet_packet::tcp::ipv6_checksum(
            &tcp_pkt.to_immutable(),
            &destination,
            &source,
        ));

        pkt.set_source(destination);
        pkt.set_destination(source);
        pkt.set_hop_limit(ttl);
        pkt.set_payload_length(tcp_pkt.packet().len() as u16 - size_shrink as u16);
        pkt.set_payload(&tcp_pkt.packet()[..tcp_pkt.packet().len() - size_shrink]);

        pkt.packet().to_vec()
    } else {
        let pkt = MutableIpv4Packet::owned(pkt_data);
        let Some(mut pkt) = pkt else {
            tracing::error!("Invalid IPv6 packet received");
            // We just need an early return here
            return Err(WinDivertError::IOError(std::io::Error::last_os_error()));
        };

        let mut new_payload = pkt.payload().to_vec();
        new_payload.resize(new_payload.len() + payload.len(), 0);
        let tcp_pkt = MutableTcpPacket::owned(new_payload);
        let Some(mut tcp_pkt) = tcp_pkt else {
            tracing::error!("Invalid TCP packet received");
            return Err(WinDivertError::IOError(std::io::Error::last_os_error()));
        };
        let size_shrink = (tcp_pkt.get_data_offset() as usize - 5) * 4;

        tcp_pkt.set_flags(0);
        let source_port = tcp_pkt.get_source();
        let destination_port = tcp_pkt.get_destination();
        tcp_pkt.set_source(destination_port);
        tcp_pkt.set_destination(source_port);
        tcp_pkt.set_sequence(rand::random());
        tcp_pkt.set_acknowledgement(0);
        tcp_pkt.set_data_offset(5);
        tcp_pkt.set_options(&[]);
        tcp_pkt.set_payload(payload);

        let source = pkt.get_source();
        let destination = pkt.get_destination();
        tracing::debug!(
            "{}:{} ====SYN+ACK===> {}:{}",
            source,
            source_port,
            destination,
            destination_port
        );
        tracing::debug!(
            "{}:{} <===FAKEPKT==== {}:{}",
            source,
            source_port,
            destination,
            destination_port
        );

        tcp_pkt.set_checksum(pnet_packet::tcp::ipv4_checksum(
            &tcp_pkt.to_immutable(),
            &destination,
            &source,
        ));

        pkt.set_source(destination);
        pkt.set_destination(source);
        pkt.set_ttl(ttl);
        pkt.set_total_length(20 + tcp_pkt.packet().len() as u16 - size_shrink as u16);
        pkt.set_payload(&tcp_pkt.packet()[..tcp_pkt.packet().len() - size_shrink]);
        pkt.set_checksum(pnet_packet::ipv4::checksum(&pkt.to_immutable()));

        pkt.packet().to_vec()
    };

    new_pkt.data = Cow::Owned(new_pkt_data);
    new_pkt.address.set_outbound(true);

    let checksum_flags = ChecksumFlags::new()
        .set_no_icmp()
        .set_no_icmpv6()
        .set_no_udp();
    unsafe {
        // We can only choose reinterpret_cast here
        // SAFETY: the L here can only be either NetworkLayer or ForwardLayer, and it's
        // in a PhantomData that doesn't even matter
        let new_pkt = &mut new_pkt as *mut _;

        if std::any::TypeId::of::<L>() == std::any::TypeId::of::<NetworkLayer>() {
            (*(new_pkt as *mut WinDivertPacket<NetworkLayer>))
                .recalculate_checksums(checksum_flags)?;
        } else if std::any::TypeId::of::<L>() == std::any::TypeId::of::<ForwardLayer>() {
            (*(new_pkt as *mut WinDivertPacket<ForwardLayer>))
                .recalculate_checksums(checksum_flags)?;
        } else {
            unreachable!()
        }
    }

    Ok(new_pkt)
}

pub trait WinDivertHelper<L: WinDivertLayerTrait> {
    fn recv<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
    ) -> Result<WinDivertPacket<'a, L>, WinDivertError>;

    fn send(&self, packet: &WinDivertPacket<L>) -> Result<u32, WinDivertError>;
}

impl WinDivertHelper<NetworkLayer> for Arc<WinDivert<NetworkLayer>> {
    fn recv<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
    ) -> Result<WinDivertPacket<'a, NetworkLayer>, WinDivertError> {
        (**self).recv(buffer)
    }

    fn send(&self, packet: &WinDivertPacket<NetworkLayer>) -> Result<u32, WinDivertError> {
        (**self).send(packet)
    }
}

impl WinDivertHelper<ForwardLayer> for Arc<WinDivert<ForwardLayer>> {
    fn recv<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
    ) -> Result<WinDivertPacket<'a, ForwardLayer>, WinDivertError> {
        (**self).recv(buffer)
    }

    fn send(&self, packet: &WinDivertPacket<ForwardLayer>) -> Result<u32, WinDivertError> {
        (**self).send(packet)
    }
}

pub fn divert_handler<L: WinDivertLayerTrait + 'static>(
    divert: impl WinDivertHelper<L>,
    http_hostname: impl AsRef<str>,
    ttl: u8,
    cancellation_token: Arc<AtomicBool>,
) -> Result<(), WinDivertError> {
    let fake_payload = fake_payload_http(http_hostname.as_ref());

    let mut buffer = Vec::<u8>::with_capacity(WINDIVERT_MTU_MAX as _);
    // SAFETY: Here the buffer is used for FFI (as the intermediate buffer by
    // WinDivert wrapper), no need to initialize
    #[allow(clippy::uninit_vec)]
    unsafe {
        buffer.set_len(WINDIVERT_MTU_MAX as _)
    };

    loop {
        if cancellation_token.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }

        let packet = divert.recv(Some(&mut buffer))?;
        let fake_packet = fake_packet(ttl, &fake_payload, &packet)?;
        divert.send(&fake_packet)?;
        divert.send(&packet)?;
    }

    Ok(())
}
