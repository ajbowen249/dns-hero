extern crate base64;
use base64::{ encode, decode };

use super::data::{ Packet, DecomposedPacket, Question, Label };
use super::enums::*;
use super::doh::*;
use super::udp::*;
use super::daemon::run_dns_daemon;

enum Authority {
    CBSecurity,
    CBAdult,
    CBFamily,
    Google,
    CloudFlare,
}

enum Transport {
    UDP,
    DoH,
}

pub fn b64(args: &Vec<String>) {
    if args.len() < 3 {
        println!("Missing required domain arg (www.example.com, etc.)");
        return
    }

    let mut packet = DecomposedPacket::new();
    packet.id = 0x1234;

    for i in 2..args.len() {
        packet.questions.push(Question {
            label: Label::Domain(args[i].clone()),
            qtype: Type::A,
            qclass: Class::Internet,
        });
    }

    let raw_packet = packet.to_raw();

    let packet_b64 = encode(&raw_packet.data);
    println!("{}", packet_b64);
}

pub fn explain(args: &Vec<String>) {
    if args.len() < 3 {
        println!("Missing required packet base64");
        return
    }

    let raw_packet_data = decode(&args[2]).expect("Invalid base64.");
    let raw_packet = Packet::from_vec(&raw_packet_data);
    let packet = DecomposedPacket::from_packet(&raw_packet);

    println!("{}", packet);
}

pub fn resolve(args: &Vec<String>) {
    if args.len() < 3 {
        println!("Missing required domain arg (www.example.com, etc.)");
        return
    }

    let mut packet = DecomposedPacket::new();
    packet.id = 0x1234;

    packet.questions.push(Question {
        label: Label::Domain(args[2].clone()),
        qtype: Type::A,
        qclass: Class::Internet,
    });

    let raw_packet = packet.to_raw();

    let mut transport = Transport::UDP;
    let mut authority = Authority::CBAdult;

    for i in 3..args.len() {
        match args[i].as_str() {
            "--doh" => transport = Transport::DoH,
            "--cb-family" => authority = Authority::CBFamily,
            "--cb-security" => authority = Authority::CBSecurity,
            "--cloudflare" => authority = Authority::CloudFlare,
            "--google" => authority = Authority::Google,
            _ => {},
        }
    }

    let authority_address = String::from(match (&transport, &authority) {
        (Transport::UDP, Authority::CBSecurity) => CLEAN_BROWSING_SECURITY_DNS_IP,
        (Transport::UDP, Authority::CBAdult) => CLEAN_BROWSING_ADULT_DNS_IP,
        (Transport::UDP, Authority::CBFamily) => CLEAN_BROWSING_FAMILY_DNS_IP,
        (Transport::UDP, Authority::CloudFlare) => CLOUDFLARE_DNS_IP,
        (Transport::UDP, Authority::Google) => GOOGLE_DNS_IP,
        (Transport::DoH, Authority::CBSecurity) => CLEAN_BROWSING_SECURITY_URL,
        (Transport::DoH, Authority::CBAdult) => CLEAN_BROWSING_ADULT_URL,
        (Transport::DoH, Authority::CBFamily) => CLEAN_BROWSING_FAMILY_URL,
        (Transport::DoH, Authority::CloudFlare) => CLOUDFLARE_URL,
        (Transport::DoH, Authority::Google) => GOOGLE_URL,
    });

    println!("{}", DecomposedPacket::from_packet(&match transport {
        Transport::DoH => {
            // DoH doesn't like padding
            let packet_b64 = encode(&raw_packet.data).replace("=", "");
            resolve_doh(&authority_address, &packet_b64)
        },
        Transport::UDP => Packet::init_from_full(exchange_udp(&raw_packet.data, &authority_address)),
    }));
}

pub fn daemon(_args: &Vec<String>) {
    run_dns_daemon();
}
