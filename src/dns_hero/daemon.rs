extern crate base64;
use base64::encode;

use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::thread;
use std::net::UdpSocket;

use super::udp::*;
use super::doh::*;
use super::data::*;
use super::enums::*;
use super::util::*;

enum BlockAllowStatus {
    Neutral,
    Block,
    Allow,
}

pub fn run_dns_daemon() {
    let (tx_udp, rx_udp): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
    let (tx_udp_r, rx_udp_r): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();

    let (tx_doh, rx_doh): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
    let (tx_doh_r, rx_doh_r): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();

    thread::spawn(move || {
        let address = String::from(CLEAN_BROWSING_SECURITY_DNS_IP);
        loop {
            let request = rx_udp.recv().expect("Failed to get request");
            let response = exchange_udp(&request, &address);
            tx_udp_r.send(response).expect("Failed to reply.");
        }
    });

    thread::spawn(move || {
        let address = String::from(CLEAN_BROWSING_FAMILY_URL);
        loop {
            let request = rx_doh.recv().expect("Failed to get request");
            let packet_b64 = encode(&request).replace("=", "");
            let response = resolve_doh(&address, &packet_b64);
            tx_doh_r.send(response.data).expect("Failed to reply.");
        }
    });

    let socket = UdpSocket::bind("127.0.0.1:53").expect("Could not open UDP socket (you probably aren't root.)");

    loop {
        let mut buf = [0; 65536];
        let (received_bytes, address) = socket.recv_from(&mut buf).expect("Error receiving data");

        let packet = buf[..received_bytes].to_vec();

        tx_udp.send(packet.clone()).expect("Failed to send request");
        tx_doh.send(packet.clone()).expect("Failed to send request");

        let parsed_packet = DecomposedPacket::from_packet(&Packet::from_vec(&packet));
        println!("Resolve\n{}", parsed_packet);

        // Pretend for sake of example that this takes a while
        let block_status = get_block_allow_status(&parsed_packet);
        let block_res = make_block_packet(parsed_packet.clone());

        let main_res = rx_udp_r.recv().expect("Failed to receive");
        let authority_res = rx_doh_r.recv().expect("Failed to receive");

        let response_packet = match block_status {
            BlockAllowStatus::Block => block_res, // Blocked. Don't even bother with network result
            BlockAllowStatus::Allow => main_res, // Allowed. Don't worry about what CB said
            BlockAllowStatus::Neutral => {
                if authority_blocked_request(&authority_res) {
                    println!("Blocking via CB");
                    block_res // CB said to block, so block
                } else {
                    // We're not blocking, but the authority may have enforced safe search
                    println!("List and authority are neutral");
                    authority_res
                }
            }
        };

        println!("Responding with \n{}", DecomposedPacket::from_packet(&Packet::from_vec(&response_packet)));

        socket.send_to(&response_packet, address).expect("Failed to send response.");
    }
}

const BLOCK_LIST: [&str; 1]= [
    "lego.com",
];

const ALLOW_LIST: [&str; 1]= [
    "reddit.com",
];

fn get_block_allow_status(parsed_packet: &DecomposedPacket) -> BlockAllowStatus {
    if parsed_packet.questions.len() <= 0 {
        return BlockAllowStatus::Neutral
    }

    match &parsed_packet.questions[0].label {
        Label::Pointer(_) => BlockAllowStatus::Neutral,
        Label::Domain(domain_value) => {
            let domain_str = domain_value.as_str();

            if BLOCK_LIST.iter().any(|val| val == &domain_str) {
                println!("Blocking via block list");
                BlockAllowStatus::Block
            } else if ALLOW_LIST.iter().any(|val| val == &domain_str) {
                println!("Allowing via allow list");
                BlockAllowStatus::Allow
            } else {
                BlockAllowStatus::Neutral
            }
        }
    }
}

fn make_block_packet(mut work_packet: DecomposedPacket) -> Vec<u8> {
    work_packet.answers.push(Resource {
        label: work_packet.questions[0].label.clone(),
        rtype: Type::A,
        rclass: Class::Internet,
        ttl: 10,
        length: 4,
        data: vec![208, 185, 195, 92],
    });

    work_packet.is_response = true;
    work_packet.response_code = ResponseCode::NoError;

    work_packet.to_raw().data
}

const CLEAN_BROWSING_AUTHORITY: &str = "cleanbrowsing.rpz.noc.org";

fn authority_blocked_request(packet: &Vec<u8>) -> bool {
    let nice_packet = DecomposedPacket::from_packet(&Packet::from_vec(packet));
    match nice_packet.response_code {
        ResponseCode::NXDomain => {
            nice_packet.authorities.into_iter().any(|authority| {
                match authority.rtype {
                    Type::SOA => {
                        match parse_label(&authority.data, 0).0 {
                            Label::Pointer(_) => false,
                            Label::Domain(val) => val.as_str() == CLEAN_BROWSING_AUTHORITY,
                        }
                    },
                    _ => false,
                }
            })
        },
        _ => false,
    }
}
