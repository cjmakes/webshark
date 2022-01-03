use binread::*;
use std::net::IpAddr;

use pnet_packet::{ethernet, icmp, ip, ipv4, tcp, udp};

pub struct PacketCapture {
    pub header: GlobalHeader,
    pub records: Vec<Record>,
}

pub struct PacketCaptureView<'a> {
    pub records: Vec<&'a Record>,
}

impl PacketCapture {
    pub fn new<R: BinReaderExt>(reader: &mut R) -> Self {
        let mut pc = PacketCapture {
            header: GlobalHeader::read(reader).unwrap(),
            records: Vec::<Record>::default(),
        };

        while let Ok(pkt) = Record::read(reader) {
            pc.records.push(pkt);
        }
        pc
    }

    pub fn view(&self) -> PacketCaptureView {
        PacketCaptureView {
            records: self.records.iter().collect(),
        }
    }

    pub fn filter(&self, pred: Box<dyn Fn(&Record) -> bool>) -> PacketCaptureView {
        PacketCaptureView {
            records: self.records.iter().filter(|pkt| pred(pkt)).collect(),
        }
    }
}

pub fn compile_query(query: &str) -> Box<dyn Fn(&Record) -> bool> {
    let qip = query.parse::<IpAddr>().unwrap();
    Box::new(move |pkt| {
        let l1 = pnet_packet::ethernet::EthernetPacket::new(&pkt.payload).unwrap();
        let l2 = match l1.get_ethertype() {
            ethernet::EtherTypes::Ipv4 => ipv4::Ipv4Packet::new(&pkt.payload[14..]).unwrap(),
            _ => panic!(),
        };
        l2.get_source().eq(&qip)
    })
}

#[derive(BinRead, Debug)]
//TODO: Find a way to make use of magic number to determine endianness
#[br(magic = b"\xd4\xc3\xb2\xa1")]
pub struct GlobalHeader {
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: u32,
    pub sigfigs: u32,
    pub snaplan: u32,
    pub network: u32,
}

#[derive(BinRead)]
pub struct Record {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub incl_len: u32,
    pub orig_len: u32,
    #[br(count = incl_len)]
    pub payload: Vec<u8>,
}

pub struct ParsedRecord<'a> {
    l2: pnet_packet::ethernet::EthernetPacket<'a>,
    l3: pnet_packet::ipv4::Ipv4Packet<'a>,
    l4: L4Packet<'a>,
    l7: L7Packet<'a>,
}

#[derive(Debug)]
enum L4Packet<'a> {
    Udp(pnet_packet::udp::UdpPacket<'a>),
    Tcp(pnet_packet::tcp::TcpPacket<'a>),
    Icmp(pnet_packet::icmp::IcmpPacket<'a>),
    Unknown(&'a [u8]),
}

impl<'a> L4Packet<'a> {
    fn get_source(&self) -> Option<u16> {
        match self {
            L4Packet::Tcp(p) => Some(p.get_source()),
            L4Packet::Udp(p) => Some(p.get_source()),
            L4Packet::Icmp(_) => None,
            L4Packet::Unknown(_) => None,
        }
    }
    fn get_destination(&self) -> Option<u16> {
        match self {
            L4Packet::Tcp(p) => Some(p.get_destination()),
            L4Packet::Udp(p) => Some(p.get_destination()),
            L4Packet::Icmp(_) => None,
            L4Packet::Unknown(_) => None,
        }
    }
    fn get_name(&self) -> &str {
        match self {
            L4Packet::Tcp(_) => "TCP",
            L4Packet::Udp(_) => "UDP",
            L4Packet::Icmp(_) => "ICMP",
            L4Packet::Unknown(_) => "Unknown",
        }
    }
}

use crate::dns;

#[derive(Debug)]
enum L7Packet<'a> {
    Dns(dns::DnsPacket),
    Unknown(&'a [u8]),
}
impl<'a> L7Packet<'a> {
    fn get_name(&self) -> &str {
        match self {
            L7Packet::Dns(_) => "DNS",
            L7Packet::Unknown(_) => "Unknown",
        }
    }
}

pub enum Fields {
    SrcMacAddr(),
    DstMacAddr(),
    SrcIpAddr(),
    DstIpAddr(),
    L4Src(),
    L4Dst(),
    Info(),
    Protocol(),
}

impl Fields {
    pub fn name(&self) -> &str {
        match self {
            Fields::SrcMacAddr() => "SrcMacAddr",
            Fields::DstMacAddr() => "DstMacAddr",
            Fields::SrcIpAddr() => "SrcIpAddr",
            Fields::DstIpAddr() => "DstIpAddr",
            Fields::L4Src() => "L4Src",
            Fields::L4Dst() => "L4Dst",
            Fields::Info() => "Info",
            Fields::Protocol() => "Protocol",
        }
    }
}

pub trait Field {
    fn get(&self, record: &Record) -> Option<String>;
}

impl<'a> ParsedRecord<'a> {
    pub fn new(record: &'a Record) -> Self {
        let mut offset = 0;
        let l2 = ethernet::EthernetPacket::new(&record.payload).unwrap();
        offset += ethernet::EthernetPacket::minimum_packet_size();

        let l3 = match l2.get_ethertype() {
            ethernet::EtherTypes::Ipv4 => {
                let ret = ipv4::Ipv4Packet::new(&record.payload[offset..]).unwrap();
                offset += ipv4::Ipv4Packet::minimum_packet_size();
                ret
            }
            _ => panic!(),
        };

        let l4 = match l3.get_next_level_protocol() {
            ip::IpNextHeaderProtocols::Udp => {
                let ret = udp::UdpPacket::new(&record.payload[offset..]).unwrap();
                offset += udp::UdpPacket::minimum_packet_size();
                L4Packet::Udp(ret)
            }
            ip::IpNextHeaderProtocols::Tcp => {
                let ret = tcp::TcpPacket::new(&record.payload[offset..]).unwrap();
                offset += tcp::TcpPacket::minimum_packet_size();
                L4Packet::Tcp(ret)
            }
            ip::IpNextHeaderProtocols::Icmp => {
                let ret = icmp::IcmpPacket::new(&record.payload[offset..]).unwrap();
                offset += icmp::IcmpPacket::minimum_packet_size();
                L4Packet::Icmp(ret)
            }
            _ => L4Packet::Unknown(&record.payload[offset..]),
        };

        let l7 = match (&l4, l4.get_source(), l4.get_destination()) {
            (&L4Packet::Udp(_), Some(53), _) | (L4Packet::Udp(_), _, Some(53)) => {
                L7Packet::Dns(crate::dns::DnsPacket::new(&record.payload[offset..]).unwrap())
            }
            (_, _, _) => L7Packet::Unknown(&record.payload[offset..]),
        };
        Self { l2, l3, l4, l7 }
    }

    pub fn get_field(&self, field: &Fields) -> Option<String> {
        match field {
            Fields::SrcMacAddr() => Some(self.l2.get_source().to_string()),
            Fields::DstMacAddr() => Some(self.l2.get_destination().to_string()),
            Fields::SrcIpAddr() => Some(self.l3.get_source().to_string()),
            Fields::DstIpAddr() => Some(self.l3.get_source().to_string()),
            Fields::L4Src() => self.l4.get_source().map(|p| p.to_string()),
            Fields::L4Dst() => self.l4.get_destination().map(|p| p.to_string()),
            Fields::Info() => Some(match self.l7 {
                L7Packet::Unknown(_) => format!("{:?}", self.l4),
                _ => format!("{:?}", self.l7),
            }),
            Fields::Protocol() => Some(
                match self.l7 {
                    L7Packet::Unknown(_) => self.l4.get_name(),
                    _ => self.l7.get_name(),
                }
                .to_owned(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn parse_packet_capture() {
        let mut reader = File::open("dns.pcap").unwrap();
        let pc = PacketCapture::new(&mut reader);

        assert_eq!(pc.header.version_major, 2);
        assert_eq!(pc.header.version_minor, 4);
        assert_eq!(pc.records.len(), 38);
        assert_eq!(pc.records[0].orig_len, 70);
        assert_eq!(pc.records[0].incl_len, 70);
        assert_eq!(pc.records[0].ts_sec, 1112172466);
        assert_eq!(pc.records[0].ts_usec, 496046);
        assert_eq!(pc.records[0].payload.len(), 70);
    }

    #[test]
    fn test_filter() {
        let mut reader = File::open("dns.pcap").unwrap();
        let pc = PacketCapture::new(&mut reader);
        let fv = pc.filter(compile_query("192.168.170.8"));
        assert_eq!(fv.records.len(), 14);
    }
}
