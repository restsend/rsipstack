use get_if_addrs::get_if_addrs;
use rsipstack::transport::{udp::UdpConnection, SipAddr};
use rsipstack::{Error, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use stun_rs::{
    attributes::stun::XorMappedAddress, methods::BINDING, MessageClass, MessageDecoderBuilder,
    MessageEncoderBuilder, StunMessageBuilder,
};
use tokio::net::lookup_host;
use tokio::select;
use tokio::time::sleep;
use tracing::info;

pub fn get_first_non_loopback_interface() -> Result<IpAddr> {
    for i in get_if_addrs()? {
        if !i.is_loopback() {
            match i.addr {
                get_if_addrs::IfAddr::V4(ref addr) => return Ok(std::net::IpAddr::V4(addr.ip)),
                _ => continue,
            }
        }
    }
    Err(Error::Error("No IPV4 interface found".to_string()))
}

pub async fn external_by_stun(
    conn: &mut UdpConnection,
    stun_server: &str,
    expires: Duration,
) -> Result<SocketAddr> {
    info!(stun_server = %stun_server, "getting external IP by STUN server");
    let msg = StunMessageBuilder::new(BINDING, MessageClass::Request).build();

    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer: [u8; 150] = [0x00; 150];
    encoder
        .encode(&mut buffer, &msg)
        .map_err(|e| crate::Error::Error(e.to_string()))?;

    let mut addrs = lookup_host(stun_server).await?;
    let target = addrs
        .next()
        .ok_or_else(|| crate::Error::Error("STUN server address not found".to_string()))?;

    conn.send_raw(
        &buffer,
        &SipAddr {
            addr: target.into(),
            r#type: None,
        },
    )
    .await?;

    let mut buf = [0u8; 2048];
    let (len, _) = select! {
        _ = sleep(expires) => {
            info!(stun_server = %stun_server, "stun timeout");
            return Err(Error::Error("STUN server timeout".to_string()));
        }
        r = conn.recv_raw(&mut buf) => {
             r?
        }
    };

    let decoder = MessageDecoderBuilder::default().build();
    let (resp, _) = decoder
        .decode(&buf[..len])
        .map_err(|e| crate::Error::Error(e.to_string()))?;

    let xor_addr = resp
        .get::<XorMappedAddress>()
        .ok_or(crate::Error::Error(
            "XorMappedAddress attribute not found".to_string(),
        ))?
        .as_xor_mapped_address()
        .map_err(|e| crate::Error::Error(e.to_string()))?;
    let socket: &SocketAddr = xor_addr.socket_address();
    info!(external_ip = %socket, "external IP");
    conn.external = Some(SipAddr {
        r#type: Some(rsip::transport::Transport::Udp),
        addr: socket.to_owned().into(),
    });
    Ok(socket.clone())
}

#[tokio::test]
async fn test_external_with_stun() -> Result<()> {
    let addrs = tokio::net::lookup_host("restsend.com:3478").await?;
    for addr in addrs {
        info!(stun_server = %addr, "stun server");
    }
    let mut peer_bob = UdpConnection::create_connection("0.0.0.0:0".parse()?, None).await?;
    let expires = Duration::from_secs(5);
    external_by_stun(&mut peer_bob, "restsend.com:3478", expires).await?;
    info!(external_ip = ?peer_bob.get_addr(), "external IP");
    Ok(())
}
