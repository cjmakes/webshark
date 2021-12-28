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

#[derive(PartialEq, Default, Debug)]
pub struct DnsPacket {
    pub id: u16,
    pub control: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
    pub authoritys: Vec<DnsResourceRecord>,
    pub additionals: Vec<DnsResourceRecord>,
}

#[derive(PartialEq, Debug)]
pub struct DnsQuestion {
    pub labels: Vec<String>,
    pub typ: DnsType,
    pub class: DnsClass,
}

#[derive(PartialEq, Default, Debug)]
struct DnsQuestionBuilder {
    pub labels: Vec<DomainNameLabel>,
    pub typ: u16,
    pub class: u16,
}

#[derive(PartialEq, Debug)]
pub struct DnsResourceRecord {
    pub labels: Vec<String>,
    pub typ: DnsType,
    pub class: DnsClass,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

#[derive(PartialEq, Debug)]
pub struct DnsResourceRecordBuilder {
    pub labels: Vec<DomainNameLabel>,
    pub typ: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

use nom::{bytes::complete::*, multi, number::complete::*, IResult};

impl DnsPacket {
    pub fn new(data: &[u8]) -> Option<DnsPacket> {
        let (_, pkt) = DnsPacket::parse(data).ok()?;
        Some(pkt)
    }

    fn parse(data: &[u8]) -> IResult<&[u8], DnsPacket> {
        let (input, id) = be_u16(data)?;
        let (input, control) = be_u16(input)?;
        let (input, qd_count) = be_u16(input)?;
        let (input, an_count) = be_u16(input)?;
        let (input, ns_count) = be_u16(input)?;
        let (input, ar_count) = be_u16(input)?;

        let (input, questions) = multi::count(parse_dns_question, qd_count.into())(input)?;
        let (input, answers) = multi::count(parse_dns_resource_record, an_count.into())(input)?;
        let (input, authoritys) = multi::count(parse_dns_resource_record, ns_count.into())(input)?;
        let (input, additionals) = multi::count(parse_dns_resource_record, ar_count.into())(input)?;

        let questions = questions.into_iter().map(|q| q.build(data)).collect();
        let answers = answers.into_iter().map(|rr| rr.build(data)).collect();
        let authoritys = authoritys.into_iter().map(|rr| rr.build(data)).collect();
        let additionals = additionals.into_iter().map(|rr| rr.build(data)).collect();

        Ok((
            input,
            DnsPacket {
                id,
                control,
                questions,
                answers,
                authoritys,
                additionals,
            },
        ))
    }
}

impl DnsQuestionBuilder {
    fn build(self, input: &[u8]) -> DnsQuestion {
        DnsQuestion {
            labels: self
                .labels
                .into_iter()
                .filter_map(|l| l.deref(input))
                .flat_map(|v| v.into_iter())
                .collect(),
            typ: DnsType::new(self.typ),
            class: DnsClass::new(self.class),
        }
    }
}
impl DnsResourceRecordBuilder {
    fn build(self, input: &[u8]) -> DnsResourceRecord {
        DnsResourceRecord {
            labels: self
                .labels
                .into_iter()
                .filter_map(|l| l.deref(input))
                .flat_map(|v| v.into_iter())
                .collect(),
            typ: DnsType::new(self.typ),
            class: DnsClass::new(self.class),
            ttl: self.ttl,
            rdata: self.rdata,
        }
    }
}

impl DomainNameLabel {
    fn deref(self, input: &[u8]) -> Option<Vec<String>> {
        match self {
            DomainNameLabel::Value(v) => Some(vec![v]),
            DomainNameLabel::Offset(o) => Some(offset_to_values(input, o)),
            DomainNameLabel::Null() => None,
        }
    }
}

fn offset_to_values(input: &[u8], offset: u16) -> Vec<String> {
    let (_, labels) = parse_dns_labels(&input[offset as usize..]).unwrap_or((input, Vec::new()));

    labels
        .into_iter()
        .filter_map(|l| l.deref(input))
        .flat_map(|v| v.into_iter())
        .collect()
}

fn parse_dns_question(input: &[u8]) -> IResult<&[u8], DnsQuestionBuilder> {
    let (input, labels) = parse_dns_labels(input)?;
    let (input, typ) = be_u16(input)?;
    let (input, class) = be_u16(input)?;
    Ok((input, DnsQuestionBuilder { labels, typ, class }))
}

fn parse_dns_resource_record(input: &[u8]) -> IResult<&[u8], DnsResourceRecordBuilder> {
    let (input, labels) = parse_dns_labels(input)?;
    let (input, typ) = be_u16(input)?;
    let (input, class) = be_u16(input)?;
    let (input, ttl) = be_u32(input)?;
    let (input, rdata_len) = be_u16(input)?;
    let (input, rdata) = take(rdata_len)(input)?;
    Ok((
        input,
        DnsResourceRecordBuilder {
            labels,
            typ,
            class,
            ttl,
            rdata: rdata.to_owned(),
        },
    ))
}

fn parse_dns_labels(input: &[u8]) -> IResult<&[u8], Vec<DomainNameLabel>> {
    let (input, (mut labels, null_or_ptr)) =
        multi::many_till(parse_dns_label, parse_null_or_pointer)(input)?;
    labels.push(null_or_ptr);
    Ok((input, labels))
}

// TODO: Replace this with some nom combinators probably
fn parse_null_or_pointer(input: &[u8]) -> IResult<&[u8], DomainNameLabel> {
    let (input, len_ptr_null) = be_u8(input)?;
    if len_ptr_null >> 6 == 0b11 {
        let (input, offset2) = be_u8(input)?;
        let offset: u16 = (((len_ptr_null & 0b00111111) as u16) << 8) | offset2 as u16;
        return Ok((input, DomainNameLabel::Offset(offset)));
    }
    if len_ptr_null == b'\x00' {
        return Ok((input, DomainNameLabel::Null()));
    }
    Err(nom::Err::Error(nom::error_position!(
        input,
        nom::error::ErrorKind::Tag
    )))
}

fn parse_dns_label<'a>(input: &'a [u8]) -> IResult<&'a [u8], DomainNameLabel> {
    let (input, offset_or_len) = be_u8(input)?;
    match offset_or_len >> 6 {
        0b00 => {
            let (input, lbl) = take(offset_or_len)(input)?;
            Ok((
                input,
                DomainNameLabel::Value(std::string::String::from_utf8(lbl.to_owned()).unwrap()),
            ))
        }
        0b11 => {
            let (input, offset2) = be_u8(input)?;
            let offset: u16 = (((offset_or_len & 0b00111111) as u16) << 8) | offset2 as u16;
            Ok((input, DomainNameLabel::Offset(offset)))
        }
        _ => Ok((input, DomainNameLabel::Null())),
    }
}

#[derive(Debug, PartialEq)]
pub enum DomainNameLabel {
    Offset(u16),
    Value(String),
    Null(),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_null_or_pointer_null() {
        let input = b"\x00";
        let (input, term) = parse_null_or_pointer(input).unwrap();
        assert_eq!(input, b"");
        assert_eq!(term, DomainNameLabel::Null());
    }
    #[test]
    fn test_parse_null_or_pointer_ptr() {
        let input = b"\xc0\xab";
        let (input, term) = parse_null_or_pointer(input).unwrap();
        assert_eq!(input, b"");
        assert_eq!(term, DomainNameLabel::Offset(0xab));
    }
    #[test]
    fn test_parse_domain_label_simple() {
        let input = b"\x03www";
        let (input, label) = parse_dns_label(input).unwrap();
        assert_eq!(input, b"");
        assert_eq!(label, DomainNameLabel::Value("www".to_owned()));
    }
    #[test]
    fn test_parse_domain_label_offset() {
        let input = b"\xc0\x04";
        let (input, label) = parse_dns_label(input).unwrap();
        assert_eq!(input, b"");
        assert_eq!(label, DomainNameLabel::Offset(4));
    }
    #[test]
    fn test_parse_domain_labels_simple() {
        let input = b"\x03www\x0acloudflare\x03com\x00";
        let (input, labels) = parse_dns_labels(input).unwrap();
        assert_eq!(input, b"");
        assert_eq!(labels[0], DomainNameLabel::Value("www".to_owned()));
        assert_eq!(labels[1], DomainNameLabel::Value("cloudflare".to_owned()));
        assert_eq!(labels[2], DomainNameLabel::Value("com".to_owned()));
    }
    #[test]
    fn test_parse_domain_labels_mixed() {
        let input = b"\x03www\xc0\xaa";
        let (input, labels) = parse_dns_labels(input).unwrap();
        assert_eq!(input, b"");
        assert_eq!(labels[0], DomainNameLabel::Value("www".to_owned()));
        assert_eq!(labels[1], DomainNameLabel::Offset(0xaa));
    }
    #[test]
    fn test_parse_dns_question() {
        let input = b"\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x10\x00\x01";
        let (input, question) = parse_dns_question(input).unwrap();
        assert_eq!(input, b"");
        assert_eq!(
            question.labels[0],
            DomainNameLabel::Value("google".to_owned())
        );
        assert_eq!(question.labels[1], DomainNameLabel::Value("com".to_owned()));
        assert_eq!(DnsType::new(question.typ), dns_types::TXT);
        assert_eq!(DnsClass::new(question.class), dns_class::IN);
    }

    #[test]
    fn test_parse_dns_resource_record() {
        let input = b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x01\x0e\x00\x10\x0f\x76\x3d\x73\x70\x66\x31\x20\x70\x74\x72\x20\x3f\x61\x6c\x6c";
        let (input, record) = parse_dns_resource_record(input).unwrap();
        assert_eq!(input, b"");
        assert_eq!(record.ttl, 270);
        assert_eq!(record.labels[0], DomainNameLabel::Offset(0x000c));
        assert_eq!(DnsType::new(record.typ), dns_types::TXT);
        assert_eq!(DnsClass::new(record.class), dns_class::IN);
        assert_eq!(
            record.rdata,
            b"\x0f\x76\x3d\x73\x70\x66\x31\x20\x70\x74\x72\x20\x3f\x61\x6c\x6c"
        );
    }
    #[test]
    fn test_build_dns_packet() {
        let input = b"\x10\x32\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x10\x00\x01\xc0\x0c\x00\x10\x00\x01\x00\x00\x01\x0e\x00\x10\x0f\x76\x3d\x73\x70\x66\x31\x20\x70\x74\x72\x20\x3f\x61\x6c\x6c";

        let (input, pkt) = DnsPacket::parse(input).unwrap();
        assert_eq!(input, b"");
        assert_eq!(pkt.answers[0].labels[0], "google".to_owned());
    }
}
