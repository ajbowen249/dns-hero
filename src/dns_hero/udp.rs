use std::fmt::Write;
use std::net::UdpSocket;

pub const CLEAN_BROWSING_SECURITY_DNS_IP: &str = "185.228.168.9";
pub const CLEAN_BROWSING_ADULT_DNS_IP:    &str = "185.228.168.10";
pub const CLEAN_BROWSING_FAMILY_DNS_IP:   &str = "185.228.168.168";
pub const CLOUDFLARE_DNS_IP:              &str = "1.1.1.1";
pub const GOOGLE_DNS_IP:                  &str = "8.8.8.8";

pub fn exchange_udp(output_packet: &Vec<u8>, ip_address: &String) -> Vec<u8> {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Could not open UDP socket");

    let mut dest_socket_addr = String::new();
    write!(&mut dest_socket_addr, "{}:53", ip_address).expect("Could not create destination socket address");

    socket.connect(dest_socket_addr).expect("Could not conenct to remote");
    socket.send(&output_packet).expect("Error sending outbound packet");

    let mut buf = [0; 65536];
    let received_bytes = socket.recv(&mut buf).expect("Error receiving data");
    buf[..received_bytes].to_vec()
}
