use binread::*;
use std::net::IpAddr;

use pnet_packet::{ethernet, icmp, ip, ipv4, tcp, udp};

// from https://wiki.wireshark.org/Development/LibpcapFileFormat
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
    l1: pnet_packet::ethernet::EthernetPacket<'a>,
    l2: pnet_packet::ipv4::Ipv4Packet<'a>,
    l3: L3Packet<'a>,
    l4: L4Packet,
}

enum L3Packet<'a> {
    Udp(pnet_packet::udp::UdpPacket<'a>),
    Tcp(pnet_packet::tcp::TcpPacket<'a>),
    Icmp(pnet_packet::icmp::IcmpPacket<'a>),
}

impl<'a> L3Packet<'a> {
    fn get_source(&self) -> Option<u16> {
        match self {
            L3Packet::Tcp(p) => Some(p.get_source()),
            L3Packet::Udp(p) => Some(p.get_source()),
            L3Packet::Icmp(_) => None,
        }
    }
    fn get_destination(&self) -> Option<u16> {
        match self {
            L3Packet::Tcp(p) => Some(p.get_destination()),
            L3Packet::Udp(p) => Some(p.get_destination()),
            L3Packet::Icmp(_) => None,
        }
    }
}

#[derive(Debug)]
enum L4Packet {
    Dns(crate::dns::DnsPacket),
}
impl L4Packet {
    fn get_name(&self) -> &str {
        match self {
            L4Packet::Dns(_) => "DNS",
        }
    }
}

pub enum Fields {
    SrcMacAddr(),
    DstMacAddr(),
    SrcIpAddr(),
    DstIpAddr(),
    L3Src(),
    L3Dst(),
    L4Name(),
    L4Info(),
}

impl Fields {
    pub fn name(&self) -> &str {
        match self {
            Fields::SrcMacAddr() => "SrcMacAddr",
            Fields::DstMacAddr() => "DstMacAddr",
            Fields::SrcIpAddr() => "SrcIpAddr",
            Fields::DstIpAddr() => "DstIpAddr",
            Fields::L3Src() => "L3Src",
            Fields::L3Dst() => "L3Dst",
            Fields::L4Name() => "L4Name",
            Fields::L4Info() => "L4Info",
        }
    }
}

pub trait Field {
    fn get(&self, record: &Record) -> Option<String>;
}

impl<'a> ParsedRecord<'a> {
    pub fn new(record: &'a Record) -> Self {
        let mut offset = 0;
        let l1 = ethernet::EthernetPacket::new(&record.payload).unwrap();
        offset += ethernet::EthernetPacket::minimum_packet_size();

        let l2 = match l1.get_ethertype() {
            ethernet::EtherTypes::Ipv4 => {
                let ret = ipv4::Ipv4Packet::new(&record.payload[offset..]).unwrap();
                offset += ipv4::Ipv4Packet::minimum_packet_size();
                ret
            }
            _ => panic!(),
        };

        let l3 = match l2.get_next_level_protocol() {
            ip::IpNextHeaderProtocols::Udp => {
                let ret = udp::UdpPacket::new(&record.payload[offset..]).unwrap();
                offset += udp::UdpPacket::minimum_packet_size();
                L3Packet::Udp(ret)
            }
            ip::IpNextHeaderProtocols::Tcp => {
                let ret = tcp::TcpPacket::new(&record.payload[offset..]).unwrap();
                offset += tcp::TcpPacket::minimum_packet_size();
                L3Packet::Tcp(ret)
            }
            ip::IpNextHeaderProtocols::Icmp => {
                let ret = icmp::IcmpPacket::new(&record.payload[offset..]).unwrap();
                offset += icmp::IcmpPacket::minimum_packet_size();
                L3Packet::Icmp(ret)
            }
            _ => panic!(),
        };

        let l4 = match (&l3, l3.get_source(), l3.get_destination()) {
            (&L3Packet::Udp(_), Some(53), _) | (L3Packet::Udp(_), _, Some(53)) => {
                L4Packet::Dns(crate::dns::DnsPacket::new(&record.payload[offset..]).unwrap())
            }
            (_, _, _) => panic!(),
        };
        Self { l1, l2, l3, l4 }
    }

    pub fn get_field(&self, field: &Fields) -> Option<String> {
        match field {
            Fields::SrcMacAddr() => Some(self.l1.get_source().to_string()),
            Fields::DstMacAddr() => Some(self.l1.get_destination().to_string()),
            Fields::SrcIpAddr() => Some(self.l2.get_source().to_string()),
            Fields::DstIpAddr() => Some(self.l2.get_source().to_string()),
            Fields::L3Src() => self.l3.get_source().map(|p| p.to_string()),
            Fields::L3Dst() => self.l3.get_destination().map(|p| p.to_string()),
            Fields::L4Name() => Some(self.l4.get_name().to_owned()),
            Fields::L4Info() => Some(format!("{:?}", self.l4)),
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
