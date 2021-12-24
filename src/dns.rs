use binread::*;

#[derive(Debug, PartialEq)]
pub struct DnsType(pub u16);
pub mod dns_types {
    use super::DnsType;

    pub const A: DnsType = DnsType(1); // a host address
    pub const NS: DnsType = DnsType(2); // an authoritative name server
    pub const MD: DnsType = DnsType(3); // a mail destination (Obsolete - use MX)
    pub const MF: DnsType = DnsType(4); // a mail forwarder (Obsolete - use MX)
    pub const CNAME: DnsType = DnsType(5); // the canonical name for an alias
    pub const SOA: DnsType = DnsType(6); // marks the start of a zone of authority
    pub const MB: DnsType = DnsType(7); // a mailbox domain name (EXPERIMENTAL)
    pub const MG: DnsType = DnsType(8); // a mail group member (EXPERIMENTAL)
    pub const MR: DnsType = DnsType(9); // a mail rename domain name (EXPERIMENTAL)
    pub const NULL: DnsType = DnsType(10); // a null RR (EXPERIMENTAL)
    pub const WKS: DnsType = DnsType(11); // a well known service description
    pub const PTR: DnsType = DnsType(12); // a domain name pointer
    pub const HINFO: DnsType = DnsType(13); // host information
    pub const MINFO: DnsType = DnsType(14); // mailbox or mail list information
    pub const MX: DnsType = DnsType(15); // mail exchange
    pub const TXT: DnsType = DnsType(16); // text strings

    pub const AXFR: DnsType = DnsType(252); // A request for a transfer of an entire zone
    pub const MAILB: DnsType = DnsType(253); // A request for mailbox-related records (MB, MG or MR)
    pub const MAILA: DnsType = DnsType(254); // A request for mail agent RRs (Obsolete - see MX)
                                             //*               255 A request for all records
}

impl DnsType {
    pub fn new(value: u16) -> DnsType {
        DnsType(value)
    }
}

#[derive(Debug, PartialEq)]
pub struct DnsClass(pub u16);
pub mod dns_class {
    use super::DnsClass;

    pub const IN: DnsClass = DnsClass(1); //the Internet
    pub const CS: DnsClass = DnsClass(2); //the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    pub const CH: DnsClass = DnsClass(3); //the CHAOS class
    pub const HS: DnsClass = DnsClass(4); //Hesiod [Dyer 87]
}

impl DnsClass {
    pub fn new(value: u16) -> DnsClass {
        DnsClass(value)
    }
}

// TODO: Handle compression
#[derive_binread]
#[br(big)]
#[derive(PartialEq, Debug)]
pub struct DnsPacket {
    pub id: u16,
    pub control: u16,
    #[br(temp)]
    pub qd_count: u16,
    #[br(temp)]
    pub an_count: u16,
    #[br(temp)]
    pub ns_count: u16,
    #[br(temp)]
    pub ar_count: u16,
    #[br(count = qd_count)]
    pub questions: Vec<DnsQuestion>,
    #[br(count = an_count)]
    pub answers: Vec<DnsResourceRecord>,
    #[br(count = ns_count)]
    pub authoritys: Vec<DnsResourceRecord>,
    #[br(count = ar_count)]
    pub additionals: Vec<DnsResourceRecord>,
}

impl DnsPacket {
    pub fn new<R: BinReaderExt>(reader: &mut R) -> Self {
        Self::read(reader).unwrap()
    }
}

#[derive(BinRead, PartialEq, Debug)]
pub struct DnsQuestion {
    #[br(parse_with = until_exclusive(|lbl: &DomainNameLabel| lbl.label.is_empty()))]
    pub labels: Vec<DomainNameLabel>,
    pub typ: u16,
    pub class: u16,
}

#[derive(BinRead, PartialEq, Debug)]
pub struct DnsResourceRecord {
    #[br(parse_with = until_exclusive(|lbl: &DomainNameLabel| lbl.label.is_empty()))]
    pub labels: Vec<DomainNameLabel>,
    pub typ: u16,
    pub class: u16,
    pub ttl: u32,
    pub rd_len: u16,
    #[br(count = rd_len)]
    pub rdata: Vec<u8>,
}

#[derive_binread]
#[derive(PartialEq, Debug)]
pub struct DomainNameLabel {
    #[br(temp)]
    len: u8,
    #[br(count = len)]
    label: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap;
    use std::fs::File;

    #[test]
    fn test_dns() {
        let mut reader = File::open("dns.pcap").unwrap();
        let pc = pcap::PacketCapture::new(&mut reader);
        let mut reader = std::io::Cursor::new(&pc.records[0].payload[14 + 20 + 8..]);
        let dns = DnsPacket::read(&mut reader).unwrap();
        assert_eq!(dns.id, 0x1032);
        assert_eq!(DnsType::new(dns.questions[0].typ), dns_types::TXT);
        assert_eq!(DnsClass::new(dns.questions[0].class), dns_class::IN);

        assert_eq!(dns.questions.len(), 1);
        assert_eq!(
            dns.questions[0].labels,
            vec![
                DomainNameLabel {
                    label: vec![0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65]
                },
                DomainNameLabel {
                    label: vec![0x63, 0x6f, 0x6d]
                },
            ]
        );
    }
}
