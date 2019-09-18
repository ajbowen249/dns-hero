use std::iter;
use std::fmt;

use super::util::*;
use super::enums::*;

#[derive(Clone)]
pub enum Label {
    Pointer(u8),
    Domain(String),
}

impl Label {
    /// Converts the label to its raw DNS packet form
    pub fn to_raw(&self, output: &mut Vec<u8>) {
        match self {
            Label::Domain(domain) => {
                let mut label_bytes = str_domain_to_dns_domain(&domain);
                output.append(&mut label_bytes);
            },
            Label::Pointer(offset) => {
                // Set first two bits to flag pointer.
                output.push(offset | 0xC0);
                // End the label.
                output.push(0x00);
            },
        }
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Label::Domain(domain_name) => write!(f, "{}", domain_name),
            Label::Pointer(offset) => write!(f, "*{}", offset),
        }
    }
}

/// Encapsulates a DNS Resource record (answer, authority, etc.)
#[derive(Clone)]
pub struct Resource {
    pub  label: Label,
    pub  rtype: Type,
    pub rclass: Class,
    pub    ttl: u32,
    pub length: u16,
    pub   data: Vec<u8>,
}

impl Resource {
    /// Converts the resource to its raw DNS packet form
    pub fn to_raw(&self, output: &mut Vec<u8>) {
        self.label.to_raw(output);
        self.rtype.to_raw(output);
        self.rclass.to_raw(output);

        output.push(((self.ttl >> 24) & 0x000000FF) as u8);
        output.push(((self.ttl >> 16) & 0x000000FF) as u8);
        output.push(((self.ttl >> 8)  & 0x000000FF) as u8);
        output.push((self.ttl         & 0x000000FF) as u8);

        output.push(((self.length >> 8) & 0x00FF) as u8);
        output.push((self.length        & 0x00FF) as u8);

        for b in &self.data {
            output.push(*b);
        }
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        coalesce_result!(match self.rtype {
            Type::A => write!(f, " {}.{}.{}.{} ", self.data[0], self.data[1], self.data[2], self.data[3]),
            Type::SOA => {
                let parse_result = parse_label(&self.data, 0);
                write!(f, "{} ", parse_result.0)
            },
            _ => write!(f, "{} bytes ", self.length),
        });
        write!(f, "({}, {}, {})", self.label, self.rtype, self.rclass)
    }
}

/// Encapsulates a DNS question
#[derive(Clone)]
pub struct Question {
    pub   label: Label,
    pub   qtype: Type,
    pub  qclass: Class,
}

impl Question {
    /// Converts the question to its raw DNS packet form
    pub fn to_raw(&self, output: &mut Vec<u8>) {
        self.label.to_raw(output);
        self.qtype.to_raw(output);
        self.qclass.to_raw(output);
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}, {})", self.label, self.qtype, self.qclass)
    }
}

#[derive(Clone)]
pub struct DecomposedPacket {
    pub                 id: u16,
    pub          questions: Vec<Question>,
    pub            answers: Vec<Resource>,
    pub        authorities: Vec<Resource>,
    pub additional_records: Vec<Resource>,
}

impl DecomposedPacket {
    pub fn from_packet(raw: &Packet) -> DecomposedPacket {
        let id = raw.get_id();
        let mut packet_index = 12; // Start at end of header

        let mut questions = Vec::<Question>::new();
        packet_index = collect_resources(&mut questions, parse_question, &raw.data, packet_index, raw.get_question_count());

        let mut answers = Vec::<Resource>::new();
        packet_index = collect_resources(&mut answers, parse_resource, &raw.data, packet_index, raw.get_answer_count());

        let mut authorities = Vec::<Resource>::new();
        packet_index = collect_resources(&mut authorities, parse_resource, &raw.data, packet_index, raw.get_authority_count());

        let mut additional_records = Vec::<Resource>::new();
        collect_resources(&mut additional_records, parse_resource, &raw.data, packet_index, raw.get_additional_record_count());

        DecomposedPacket { id, questions, answers, authorities, additional_records }
    }

    pub fn new() -> DecomposedPacket {
        DecomposedPacket { id: 0, questions: vec![], answers: vec![], authorities: vec![], additional_records: vec![] }
    }

    pub fn to_raw(&self) -> Packet {
        let mut packet = Packet::init();

        packet.set_id(self.id);
        packet.set_question_count(self.questions.len() as u16);
        packet.set_answer_count(self.answers.len() as u16);
        packet.set_authority_count(self.authorities.len() as u16);
        packet.set_additional_record_count(self.additional_records.len() as u16);
        for question in &self.questions {
            question.to_raw(&mut packet.data);
        }

        for answer in &self.answers {
            answer.to_raw(&mut packet.data);
        }

        for authority in &self.authorities {
            authority.to_raw(&mut packet.data);
        }

        for additional_record in &self.additional_records {
            additional_record.to_raw(&mut packet.data);
        }

        packet
    }
}

impl fmt::Display for DecomposedPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // IMPROVE: Flags
        coalesce_result!(writeln!(f, "ID: {}", self.id));

        coalesce_result!(writeln!(f, "Questions({}):", self.questions.len()));
        for question in &self.questions {
            coalesce_result!(writeln!(f, "    {}", question));
        }

        coalesce_result!(writeln!(f, "Answers({}):", self.answers.len()));
        for answer in &self.answers {
            coalesce_result!(writeln!(f, "    {}", answer));
        }

        coalesce_result!(writeln!(f, "Authorities({}):", self.authorities.len()));
        for authority in &self.authorities {
            coalesce_result!(writeln!(f, "    {}", authority));
        }

        coalesce_result!(writeln!(f, "Additional Records({}):", self.additional_records.len()));
        for additional_record in &self.additional_records {
            coalesce_result!(writeln!(f, "    {}", additional_record));
        }

        Result::Ok(())
    }
}

/// Encapsulates a packet.
pub struct Packet {
    pub data: Vec<u8>,
}

impl Packet {
    /// Creates a new packet with everything zeroed out.
    ///
    /// Data length will be 12, a full zero packer with no questions,
    /// answers, or resources.
    pub fn init() -> Packet {
        Packet {
            data: iter::repeat(0).take(12).collect()
        }
    }

    /// Creates a new packet by moving an existing vector.
    pub fn init_from_full(data: Vec<u8>) -> Packet {
        Packet {
            data
        }
    }

    /// Creates a new packet by copying an existing vector.
    pub fn from_vec(data: &Vec<u8>) -> Packet {
        Packet {
            data: data.clone()
        }
    }

    /// Sets the ID of the packet.
    pub fn set_id(&mut self, id: u16) {
        set_u16(&mut self.data, id, 0);
    }

    /// Gets the ID of the packet.
    pub fn get_id(&self) -> u16 {
        get_u16(&self.data, 0)
    }

    /// Get the number of questions.
    pub fn get_question_count(&self) -> u16 {
        get_u16(&self.data, 4)
    }

    /// Set the number of questions.
    pub fn set_question_count(&mut self, count: u16) {
        set_u16(&mut self.data, count, 4);
    }

    /// Get the number of answers.
    pub fn get_answer_count(&self) -> u16 {
        get_u16(&self.data, 6)
    }

    /// Set the number of answers.
    pub fn set_answer_count(&mut self, count: u16) {
        set_u16(&mut self.data, count, 6);
    }

    /// Get the number of authorities.
    pub fn get_authority_count(&self) -> u16 {
        get_u16(&self.data, 8)
    }

    /// Set the number of authorities.
    pub fn set_authority_count(&mut self, count: u16) {
        set_u16(&mut self.data, count, 8);
    }

    /// Get the number of additional records.
    pub fn get_additional_record_count(&self) -> u16 {
        get_u16(&self.data, 10)
    }

    // Set the number of additional records.
    pub fn set_additional_record_count(&mut self, count: u16) {
        set_u16(&mut self.data, count, 10);
    }
}
