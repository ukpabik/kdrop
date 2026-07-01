use hickory_proto::{
    op::Message,
    rr::{RData, RecordType},
    serialize::binary::BinDecodable,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io as stdio,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket},
    sync::Arc,
};

use tokio::io::{self, AsyncBufReadExt, BufReader};

use tokio::net::UdpSocket;

const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const PORT: u16 = 5353;
const MDNS_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(MULTICAST_ADDR), PORT);

const TARGET_QNAME: &[&[u8]] = &[b"_kdrop", b"_tcp", b"_local"];

fn build_mdns_query() -> Vec<u8> {
    let mut query: Vec<u8> = Vec::new();

    // mDNS header: [TID, Attribute Bits, # of questions, # of answers, # auth RRs, # additional RRs]
    query.extend_from_slice(&[0x00, 0x00]);
    query.extend_from_slice(&[0x00, 0x00]);
    query.extend_from_slice(&[0x00, 0x01]);
    query.extend_from_slice(&[0x00, 0x00]);
    query.extend_from_slice(&[0x00, 0x00]);
    query.extend_from_slice(&[0x00, 0x00]);

    for label in TARGET_QNAME {
        query.push(label.len() as u8);
        query.extend_from_slice(label);
    }
    query.push(0x00);

    // QTYPE and QCLASS
    query.extend_from_slice(&[0x00, 0x0c]);
    query.extend_from_slice(&[0x80, 0x01]);

    query
}

fn build_mdns_response(local_ip: Ipv4Addr) -> Vec<u8> {
    // TODO: Build response with identifying information
    vec![]
}

async fn send_mdns_response(socket: &UdpSocket) -> stdio::Result<()> {
    // TODO: Probably make a wrapper struct that stores local ip instead of calling fn everytime
    let response = build_mdns_response(get_local_ip()?);

    socket.send_to(&response, MDNS_ADDR).await?;
    Ok(())
}

async fn send_mdns_query(socket: &UdpSocket) -> stdio::Result<()> {
    let query = build_mdns_query();
    socket.send_to(&query, MDNS_ADDR).await?;
    Ok(())
}

fn get_local_ip() -> stdio::Result<Ipv4Addr> {
    let socket = StdUdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;

    if let std::net::SocketAddr::V4(addr) = socket.local_addr()? {
        Ok(*addr.ip())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Could not determine IPv4 address",
        ))
    }
}

#[tokio::main]
async fn main() -> stdio::Result<()> {
    let raw_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let addr: SocketAddr = format!("0.0.0.0:{}", PORT).parse().unwrap();
    let local_ip = get_local_ip()?;

    raw_socket.set_nonblocking(true)?;
    raw_socket.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    raw_socket.set_reuse_port(true)?;

    raw_socket.bind(&addr.into())?;
    let std_socket: StdUdpSocket = raw_socket.into();
    let socket = Arc::new(UdpSocket::from_std(std_socket)?);
    socket.join_multicast_v4(MULTICAST_ADDR, local_ip)?;

    let listener = socket.clone();

    tokio::spawn(async move {
        let mut buffer = [0u8; 4096];

        loop {
            match listener.recv_from(&mut buffer).await {
                Ok((len, _)) => {
                    if len >= 12 {
                        match Message::from_bytes(&buffer[..len]) {
                            Ok(msg) => {
                                // TODO: Send a response for every query
                                for query in &msg.queries {
                                    if query.name().to_string().contains("_kdrop") {
                                        println!("THIS IS A KDROP PACKET: {}", query.name());
                                    }
                                }

                                // TODO: Write a loop for handling answers (caching device information)
                            }
                            Err(_) => println!("Unable to parse packet"),
                        }
                    }
                    // TODO: Parse packet for information.
                }
                _ => println!("Error receiving packet"),
            }
        }
    });

    println!("Type 's' and press Enter to send mDNS query.");
    println!("Type 'q' and press Enter to quit.");

    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin).lines();

    while let Some(line) = reader.next_line().await? {
        match line.trim() {
            "s" => {
                println!("Sending mDNS query...");
                //TODO: This should be changed. When sharing a file, send a query to get newly
                //cached devices, and then perform the file transfer to specified device.
                if let Err(e) = send_mdns_query(&socket).await {
                    println!("Error sending query: {}", e);
                }
            }
            "q" => {
                println!("Quitting...");
                break;
            }
            _ => {
                println!("Unknown command. Use 's' to send or 'q' to quit.");
            }
        }
    }

    Ok(())
}
