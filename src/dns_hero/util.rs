use super::data::{ Label, Question, Resource };
use super::enums::*;

pub fn set_u16(bytes: &mut Vec<u8>, value: u16, offset: usize) {
    let b1 = ((value >> 8) & 0x00FF) as u8;
    let b2 = (value & 0x00FF) as u8;

    bytes[offset] = b1;
    bytes[offset + 1] = b2;
}

pub fn get_u16(bytes: &Vec<u8>, offset: usize) -> u16{
    let mut datum: u16 = bytes[offset] as u16;
    datum <<= 8;
    datum |= bytes[offset + 1] as u16;

    datum
}

pub fn get_u32(bytes: &Vec<u8>, offset: usize) -> u32{
    let mut datum: u32 = bytes[offset] as u32;
    datum <<= 24;
    datum |= bytes[offset + 1] as u32;
    datum <<= 16;
    datum |= bytes[offset + 2] as u32;
    datum <<= 8;
    datum |= bytes[offset + 3] as u32;

    datum
}

pub fn str_domain_to_dns_domain(domain_str: &String) -> Vec<u8> {
    let parts: Vec<&str> = domain_str.split('.').collect();
    let mut bytes = Vec::<u8>::new();

    for part in parts.into_iter() {
        let part_length = part.len();

        // Label part lengths are a single byte. However, having the first two bytes set
        // signifies a QNAME pointer, so the actual range is 6 bits, 0-63.
        if part_length >= 64 {
            panic!("Error: {} longer than range of a label segment", part);
        }

        bytes.push(part_length as u8);
        for character in part.bytes() {
            bytes.push(character as u8);
        }
    }

    bytes.push(0 as u8);
    bytes
}

pub type PacketParserFn<T> = fn(&Vec<u8>, usize) -> (T, usize);

pub fn parse_label(bytes: &Vec<u8>, start: usize) -> (Label, usize) {
    // If the first two bits are set, this is a pointer.
    if bytes[start] & 0xC0 == 0xC0 {
        return (Label::Pointer(bytes[start] & 0x3F), start + 2);
    }

    let mut domain = String::new();

    let mut i = start;

    while i < bytes.len() {
        let len = bytes[i] as usize;
        if len == 0 {
            i += 1;
            break;
        }

        if !domain.is_empty() {
            domain.push('.');
        }

        let end = i + len;
        i += 1;

        while i <= end {
            domain.push(bytes[i] as char);
            i += 1;
        }
    }

    (Label::Domain(domain), i)
}

pub fn parse_question(bytes: &Vec<u8>, start: usize) -> (Question, usize) {
    let mut index = start;
    let label_result = parse_label(bytes, index);
    index = label_result.1;

    let qtype: Type = unsafe { ::std::mem::transmute(get_u16(bytes, index)) };
    index += 2;
    let qclass: Class = unsafe { ::std::mem::transmute(get_u16(bytes, index)) };
    index += 2;

    (Question {
        label: label_result.0,
        qtype,
        qclass,
    }, index)
}

pub fn parse_resource(bytes: &Vec<u8>, start: usize) -> (Resource, usize) {
    let mut index = start;
    let label_result = parse_label(bytes, index);
    index = label_result.1;

    let rtype: Type = unsafe { ::std::mem::transmute(get_u16(bytes, index)) };
    index += 2;
    let rclass: Class = unsafe { ::std::mem::transmute(get_u16(bytes, index)) };
    index += 2;

    let ttl = get_u32(bytes, index);
    index += 4;

    let length = get_u16(bytes, index);
    index += 2;

    let mut resource_data = Vec::<u8>::new();
    for _ in 0..length {
        resource_data.push(bytes[index]);
        index += 1;
    }

    (Resource {
        label: label_result.0,
        rtype,
        rclass,
        ttl,
        length,
        data: resource_data,
    }, index)
}

pub fn collect_resources<T>(receiver: &mut Vec<T>, parser: PacketParserFn<T>,
                                data: &Vec<u8>,     index: usize,
                               count: u16) -> usize {
    let mut packet_index = index;
    for _ in 0..count {
        let result = parser(data, packet_index);
        receiver.push(result.0);
        packet_index = result.1;
    }

    packet_index
}

pub fn get_flag(byte: u8, index: u8) -> bool {
    byte & (0x01 << index) != 0
}

pub fn set_flag(byte: &mut u8, index: u8, value: bool) {
    let mask = 0x01 << index;
    if value {
        *byte |= mask;
    } else {
        *byte &= !mask;
    }
}
