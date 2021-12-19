use binread::*;
use std::net::IpAddr;

use pnet_packet::{ethernet, ip, ipv4, udp};

// from https://wiki.wireshark.org/Development/LibpcapFileFormat
pub struct PacketCapture {
    pub header: GlobalHeader,
    pub records: Vec<Packet>,
}

pub struct PacketCaptureView<'a> {
    pub records: Vec<&'a Packet>,
}

impl PacketCapture {
    pub fn new<R: BinReaderExt>(reader: &mut R) -> Self {
        let mut pc = PacketCapture {
            header: GlobalHeader::read(reader).unwrap(),
            records: Vec::<Packet>::default(),
        };

        while let Ok(pkt) = Packet::read(reader) {
            pc.records.push(pkt);
        }
        pc
    }

    pub fn view(&self) -> PacketCaptureView {
        PacketCaptureView {
            records: self.records.iter().collect(),
        }
    }

    pub fn filter(&self, query: &str) -> PacketCaptureView {
        PacketCaptureView {
            records: self
                .records
                .iter()
                .filter(|pkt| PacketCapture::compile_query(query)(pkt))
                .collect(),
        }
    }

    fn compile_query(query: &str) -> Box<dyn Fn(&Packet) -> bool> {
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
pub struct Packet {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub incl_len: u32,
    pub orig_len: u32,
    #[br(count = incl_len)]
    pub payload: Vec<u8>,
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
        let fv = pc.filter("192.168.170.8");
        assert_eq!(fv.records.len(), 14);
    }
}
