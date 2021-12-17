use binread::*;

// from https://wiki.wireshark.org/Development/LibpcapFileFormat
pub struct PacketCapture {
    header: GlobalHeader,
    records: Vec<Packet>,
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
    pub fn len(&self) -> usize {
        self.records.len()
    }
}

#[derive(BinRead, Debug)]
//TODO: Find a way to make use of magic number to determine endianness
#[br(magic = b"\xd4\xc3\xb2\xa1")]
struct GlobalHeader {
    version_major: u16,
    version_minor: u16,
    thiszone: u32,
    sigfigs: u32,
    snaplan: u32,
    network: u32,
}

#[derive(BinRead)]
struct Packet {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
    #[br(count = incl_len)]
    payload: Vec<u8>,
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
}
