//use nom::{branch::alt, bytes::complete::tag, IResult};

use binread::*;

// from https://wiki.wireshark.org/Development/LibpcapFileFormat
struct PacketCapture {
    header: GlobalHeader,
    records: Vec<Packet>,
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
    use io::Cursor;

    #[test]
    fn parse_global_header() {
        let mut reader =
            Cursor::new(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        let gh: GlobalHeader = reader.read_le().unwrap();
        assert_eq!(gh.version_major, 2);
        assert_eq!(gh.version_minor, 4);
    }

    #[test]
    fn parse_packet() {}
}
