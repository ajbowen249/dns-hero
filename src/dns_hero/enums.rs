use strum_macros::{ Display };

#[derive(Copy, Clone, Display)]
#[repr(u16)]
#[allow(dead_code)]
pub enum Type {
    A =            1,
    NS =           2,
    MD =           3,
    MF =           4,
    CNAME =        5,
    SOA =          6,
    MB =           7,
    MG =           8,
    MR =           9,
    NULLDATA =    10,
    WKS =         11,
    PTR =         12,
    HINFO =       13,
    MINFO =       14,
    MX =          15,
    TXT =         16,
    RP =          17,
    AFSDB =       18,
    X25 =         19,
    ISDN =        20,
    RT =          21,
    NSAP =        22,
    NsapPtr =     23,
    SIG =         24,
    KEY =         25,
    PX =          26,
    GPOS =        27,
    AAAA =        28,
    LOC =         29,
    NXT =         30,
    EID =         31,
    NIMLOC =      32,
    SRV =         33,
    ATMA =        34,
    NAPTR =       35,
    KX =          36,
    CERT =        37,
    A6 =          38,
    DNAME =       39,
    SINK =        40,
    OPT =         41,
    APL =         42,
    DS =          43,
    SSHFP =       44,
    IPSECKEY =    45,
    RRSIG =       46,
    NSEC =        47,
    DNSKEY =      48,
    DHCID =       49,
    NSEC3 =       50,
    NSEC3PARAM =  51,
    TLSA =        52,
    SMIMEA =      53,
    // 53 is unassigned
    HIP =         55,
    NINFO =       56,
    RKEY =        57,
    TALINK =      58,
    CDS =         59,
    CDNSKEY =     60,
    OPENPGPKEY =  61,
    CSYNC =       62,
    // 62-98 are unassigned
    SPF =         99,
    UINFO =      100,
    UID =        101,
    GID =        102,
    UNSPEC =     103,
    NID =        104,
    L32 =        105,
    L64 =        106,
    LP =         107,
    EUI48 =      108,
    EUI64 =      109,
    // 110-248 are unassigned
    TKEY =       249,
    TSIG =       250,
    IXFR =       251,
    AXFR =       252,
    MAILB =      253,
    MAILA =      254,
    ANY =        255,
    URI =        256,
    CAA =        257,
    AVC =        258,
    DOA =        259,
    // 260-32767 are unassigned
    TA =         32768,
    DLV =        32769,
}

impl Type {
    pub fn to_raw(&self, output: &mut Vec<u8>) {
        let raw = *self as u16;
        output.push(((raw >> 8) & 0x00FF) as u8);
        output.push((raw & 0x00FF) as u8);
    }
}

#[derive(Copy, Clone, Display)]
#[repr(u16)]
#[allow(dead_code)]
pub enum Class {
    Internet = 1,
    // 2 is unassigned
    Chaos = 3,
    Hesiod = 4,
    // 5-253 are unassigned
    QclassNone = 254,
    QclassAny = 255,
}

impl Class {
    pub fn to_raw(&self, output: &mut Vec<u8>) {
        let raw = *self as u16;
        output.push(((raw >> 8) & 0x00FF) as u8);
        output.push((raw & 0x00FF) as u8);
    }
}

#[derive(Copy, Clone, Display)]
#[allow(dead_code)]
pub enum Opcode {
    StandardQuery =      0,
    InverseQuery =       1,
    ServerStatus =       2,
    Unassigned =         3,
    Notify =             4,
    Update =             5,
    StatefulOperations = 6,
    Unknown =            7,
}

impl Opcode {
    pub fn from_raw(raw: u8) -> Opcode {
        match raw {
            0 => Opcode::StandardQuery,
            1 => Opcode::InverseQuery,
            2 => Opcode::ServerStatus,
            3 => Opcode::Unassigned,
            4 => Opcode::Notify,
            5 => Opcode::Update,
            6 => Opcode::StatefulOperations,
            _ => Opcode::Unknown,
        }
    }
}

// Note: The spec technically is a 16-bit number with many more values set, but
// this specifically represents the four-bit rcode field of the DNS header.
#[derive(Copy, Clone, Display)]
#[allow(dead_code)]
pub enum ResponseCode {
    NoError =    0,
    FormErr =    1,
    ServFail =   2,
    NXDomain =   3,
    NotImp =     4,
    Refused =    5,
    YXDomain =   6,
    YXRRSet =    7,
    NXRRSet =    8,
    NotAuth =    9,
    NotZone =   10,
    DSOTYPENI = 11,
    Unknown =   12,
}

impl ResponseCode {
    pub fn from_raw(raw: u8) -> ResponseCode {
        match raw {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormErr,
            2 => ResponseCode::ServFail,
            3 => ResponseCode::NXDomain,
            4 => ResponseCode::NotImp,
            5 => ResponseCode::Refused,
            6 => ResponseCode::YXDomain,
            7 => ResponseCode::YXRRSet,
            8 => ResponseCode::NXRRSet,
            9 => ResponseCode::NotAuth,
            10 => ResponseCode::NotZone,
            11 => ResponseCode::DSOTYPENI,
            _ => ResponseCode::Unknown,
        }
    }
}
