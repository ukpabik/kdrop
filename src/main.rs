use hickory_proto::{op::Message, rr::RecordType, serialize::binary::BinDecodable};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashMap,
    fmt::{self, Display},
    io as stdio,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket},
    sync::Arc,
    time::Duration,
};

use tokio::{
    io::{self, AsyncBufReadExt, BufReader},
    sync::Mutex,
};
use tokio::{net::UdpSocket, time::sleep};

const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MULTICAST_PORT: u16 = 5353;
const MDNS_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(MULTICAST_ADDR), MULTICAST_PORT);

const TARGET_QNAME: [&str; 3] = ["_kdrop", "_tcp", "_local"];

#[derive(Clone, Debug)]
struct DeviceProfile {
    hostname: String,
    ip_addr: Option<IpAddr>,
}

impl Display for DeviceProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(addr) = self.ip_addr {
            write!(f, "Device {}: | IP(v4): {}", self.hostname, addr)
        } else {
            write!(f, "Device {}: | IP(v4): {}", self.hostname, "")
        }
    }
}
impl DeviceProfile {
    fn new(hostname: String, ip_addr: Option<IpAddr>) -> Self {
        let mut new_profile = Self {
            hostname,
            ip_addr: None,
        };

        if let Some(addr) = ip_addr {
            new_profile.set_ip_addr(addr);
        }

        new_profile
    }

    fn set_ip_addr(&mut self, ip_addr: IpAddr) {
        self.ip_addr = Some(ip_addr)
    }
}

// TODO: Add better comments? or none at all idk
fn build_mdns_query() -> Vec<u8> {
    let mut query: Vec<u8> = Vec::new();

    // mDNS header
    query.extend_from_slice(&[0x00, 0x00]);
    query.extend_from_slice(&[0x00, 0x00]);
    query.extend_from_slice(&[0x00, 0x01]);
    query.extend_from_slice(&[0x00, 0x00]);
    query.extend_from_slice(&[0x00, 0x00]);
    query.extend_from_slice(&[0x00, 0x00]);

    for label in TARGET_QNAME {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);

    // QTYPE and QCLASS
    query.extend_from_slice(&[0x00, 0x0c]);
    query.extend_from_slice(&[0x80, 0x01]);

    query
}

fn build_mdns_response(local_ip: Ipv4Addr) -> Vec<u8> {
    let mut response: Vec<u8> = Vec::new();

    // mDNS header
    response.extend_from_slice(&[0x00, 0x00]);
    response.extend_from_slice(&[0x84, 0x00]);
    response.extend_from_slice(&[0x00, 0x00]);
    response.extend_from_slice(&[0x00, 0x02]);
    response.extend_from_slice(&[0x00, 0x00]);
    response.extend_from_slice(&[0x00, 0x00]);

    // PTR Record
    for label in TARGET_QNAME {
        response.push(label.len() as u8);
        response.extend_from_slice(label.as_bytes());
    }
    response.push(0x00);

    response.extend_from_slice(&[0x00, 0x0c]);
    response.extend_from_slice(&[0x00, 0x01]);
    response.extend_from_slice(&[0x00, 0x00, 0x11, 0x94]);

    let mut rdata: Vec<u8> = Vec::new();

    let os_hostname = hostname::get()
        .map(|os_str| os_str.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown-device".to_string());

    let device_name = os_hostname
        .replace(' ', "-")
        .replace('.', "-")
        .to_lowercase();

    let mut combined: Vec<&str> = Vec::new();
    combined.push(device_name.as_str());
    combined.extend_from_slice(&TARGET_QNAME.clone());
    for label in &combined {
        rdata.push(label.len() as u8);
        rdata.extend_from_slice(label.as_bytes());
    }
    rdata.push(0x00);

    let rdata_length = rdata.len() as u16;
    response.extend_from_slice(&rdata_length.to_be_bytes());
    response.extend(rdata);

    // A Record
    for label in &combined {
        response.push(label.len() as u8);
        response.extend_from_slice(label.as_bytes());
    }
    response.push(0x00);

    response.extend_from_slice(&[0x00, 0x01]);
    response.extend_from_slice(&[0x80, 0x01]);
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]);

    response.extend_from_slice(&[0x00, 0x04]);
    response.extend_from_slice(&local_ip.octets());
    response
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
    let local_ip = get_local_ip()?;

    #[cfg(target_os = "windows")]
    let bind_addr = SocketAddr::new(IpAddr::V4(local_ip), MULTICAST_PORT);

    #[cfg(not(target_os = "windows"))]
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MULTICAST_PORT);

    raw_socket.set_nonblocking(true)?;
    raw_socket.set_reuse_address(true)?;

    raw_socket.set_multicast_loop_v4(true)?;

    #[cfg(not(target_os = "windows"))]
    raw_socket.set_reuse_port(true)?;

    raw_socket.bind(&bind_addr.into())?;
    let std_socket: StdUdpSocket = raw_socket.into();
    let socket = Arc::new(UdpSocket::from_std(std_socket)?);
    socket.join_multicast_v4(MULTICAST_ADDR, local_ip)?;

    let listener = socket.clone();
    let query_sock = socket.clone();

    send_mdns_query(&socket).await?;

    let device_profiles: Arc<Mutex<HashMap<String, DeviceProfile>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let listener_profile_ptr = device_profiles.clone();

    let listener_handle = tokio::spawn(async move {
        let mut buffer = [0u8; 4096];

        loop {
            match listener.recv_from(&mut buffer).await {
                Ok((len, _)) => {
                    if len >= 12 {
                        match Message::from_bytes(&buffer[..len]) {
                            Ok(msg) => {
                                for query in &msg.queries {
                                    if query.name().to_string().contains("_kdrop") {
                                        println!("THIS IS A KDROP PACKET: {}", query.name());
                                        if let Ok(_) = send_mdns_response(&listener).await {
                                            // TODO: Do we even need to do anything here?
                                            println!("Successfully sent response");
                                        } else {
                                            println!("Error sending mdns packet");
                                        }
                                    }
                                }

                                // TODO: Maybe, with the answers, we build data objects in some map.
                                // Think about this?
                                for response in &msg.answers {
                                    if response.name.to_string().contains("_kdrop") {
                                        println!("THIS IS A KDROP PACKET: {}", response.name);
                                        match response.record_type() {
                                            RecordType::PTR => {
                                                // TODO: Do something with the data?
                                                println!("DATA: {}", response.data.to_string());
                                                let device_name =
                                                    String::from(response.data.to_string().trim());

                                                let mut unwrapped_profiles =
                                                    listener_profile_ptr.lock().await;
                                                if !unwrapped_profiles.contains_key(&device_name) {
                                                    unwrapped_profiles.insert(
                                                        device_name.clone(),
                                                        DeviceProfile::new(
                                                            device_name.clone(),
                                                            None,
                                                        ),
                                                    );
                                                }
                                            }
                                            RecordType::A => {
                                                // TODO: Do something with the data?
                                                if let Some(ip_addr) = response.data.ip_addr() {
                                                    println!("IP ADDR: {}", ip_addr);
                                                    let device_name = String::from(
                                                        response.name.to_string().trim(),
                                                    );

                                                    let mut unwrapped_profiles =
                                                        listener_profile_ptr.lock().await;
                                                    if !unwrapped_profiles
                                                        .contains_key(&device_name)
                                                    {
                                                        unwrapped_profiles.insert(
                                                            device_name.clone(),
                                                            DeviceProfile::new(
                                                                device_name.clone(),
                                                                response.data.ip_addr(),
                                                            ),
                                                        );
                                                    } else {
                                                        let profile = unwrapped_profiles
                                                            .get_mut(&device_name)
                                                            .unwrap();

                                                        profile.set_ip_addr(ip_addr);
                                                    }
                                                } else {
                                                    println!("Error parsing ip addr for A record");
                                                }
                                            }
                                            _ => (),
                                        }
                                    }
                                }
                            }
                            Err(_) => println!("Unable to parse packet"),
                        }
                    }
                }
                _ => println!("Error receiving packet"),
            }
        }
    });

    let query_handle = tokio::spawn(async move {
        loop {
            if let Err(e) = send_mdns_query(&query_sock).await {
                println!("Error sending query: {}", e);
            }

            sleep(Duration::from_secs(5)).await;
        }
    });

    println!("Type 's' and press Enter to send mDNS query.");
    println!("Type 'q' and press Enter to quit.");

    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin).lines();

    //TODO: This should be changed. When sharing a file, view the list of
    //cached devices, and then perform the file transfer to specified device.
    while let Some(line) = reader.next_line().await? {
        match line.trim() {
            "s" => {
                let profiles = &device_profiles.lock().await;
                if profiles.is_empty() {
                    println!("No profiles found");
                } else {
                }
                println!("{:?}", profiles);
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

    listener_handle.abort();
    query_handle.abort();
    Ok(())
}
