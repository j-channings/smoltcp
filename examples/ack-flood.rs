#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate smoltcp;

mod utils;

use std::str::{self, FromStr};
use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use smoltcp::phy::wait as phy_wait;
use smoltcp::phy::RawSocket;
use smoltcp::wire::{EthernetAddress, Ipv4Address, IpAddress, IpCidr};
use smoltcp::iface::{NeighborCache, EthernetInterfaceBuilder, Routes};
use smoltcp::socket::{SocketSet, TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;

fn main() {
    utils::setup_logging("");

    let device = RawSocket::new("enp30s0").expect("failed to open raw socket for enp30s0");
    let fd = device.as_raw_fd();
    let address = IpAddress::from_str("10.42.0.251").unwrap();
    let port = 22u16;


    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; 64]);
    let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; 128]);
    let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

    let ethernet_addr = EthernetAddress([0x30, 0x9c, 0x23, 0x86, 0x15, 0x9f]);
    let ip_addrs = [IpCidr::new(IpAddress::v4(10, 42, 0, 1), 24)];
    let default_v4_gw = Ipv4Address::new(10, 42, 0, 251);
    let mut routes_storage = [None; 1];
    let mut routes = Routes::new(&mut routes_storage[..]);
    routes.add_default_ipv4_route(default_v4_gw).unwrap();
    let mut iface = EthernetInterfaceBuilder::new(device)
            .ethernet_addr(ethernet_addr)
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .routes(routes)
            .finalize();

    let mut sockets = SocketSet::new(vec![]);
    let tcp_handle = sockets.add(tcp_socket);

    {
        let mut socket = sockets.get::<TcpSocket>(tcp_handle);
        socket.connect((address, port), 49500).unwrap();
    }

    iface.poll(&mut sockets, Instant::now()).unwrap();
    
    {
        let mut socket = sockets.get::<TcpSocket>(tcp_handle);
        socket.send_slice(b"SSH-2.0- OpenSSH_7.4\x0d\x0a");
    }
    iface.poll(&mut sockets, Instant::now()).unwrap();
    
    {
        let mut socket = sockets.get::<TcpSocket>(tcp_handle);
        socket.start_ack_flood();
    }

    let mut tcp_active = false;
    loop {
        let timestamp = Instant::now();
        match iface.poll(&mut sockets, timestamp) {
            Ok(_) => {},
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        {
            let mut socket = sockets.get::<TcpSocket>(tcp_handle);
            if socket.is_active() && !tcp_active {
                debug!("connected");
            } else if !socket.is_active() && tcp_active {
                debug!("disconnected");
                break
            }
            tcp_active = socket.is_active();

/*
            if socket.may_recv() {
                let data = socket.recv(|data| {
                    let mut data = data.to_owned();
                    if data.len() > 0 {
                        debug!("recv data: {:?}",
                               str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)"));
                        data = data.split(|&b| b == b'\n').collect::<Vec<_>>().concat();
                        data.reverse();
                        data.extend(b"\n");
                    }
                    (data.len(), data)
                }).unwrap();
                if socket.can_send() && data.len() > 0 {
                    debug!("send data: {:?}",
                           str::from_utf8(data.as_ref()).unwrap_or("(invalid utf8)"));
                    socket.send_slice(&data[..]).unwrap();
                }
            } else if socket.may_send() {
                debug!("close");
                socket.close();
                socket.send()
            }
*/
        }

        // phy_wait(fd, iface.poll_delay(&sockets, timestamp)).expect("wait error");
    }
}