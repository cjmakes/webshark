#![feature(cursor_remaining)]

pub mod dns;
pub mod pcap;

use pnet_packet::{ethernet, ip, ipv4, udp};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

#[wasm_bindgen]
extern "C" {
    pub fn alert(s: &str);
}

#[wasm_bindgen]
pub fn parse_pcap(data: &[u8]) -> Result<(), JsValue> {
    let mut cur = std::io::Cursor::new(data);
    let pc = pcap::PacketCapture::new(&mut cur);
    render_pcap(&pc.view()).unwrap();
    Ok(())
}

#[wasm_bindgen]
pub fn filter_pcap(data: &[u8], query: &str) -> Result<(), JsValue> {
    let mut cur = std::io::Cursor::new(data);

    let fq = pcap::compile_query(query);
    let pc = pcap::PacketCapture::new(&mut cur);
    let fv = pc.filter(fq);
    render_pcap(&fv).unwrap();
    Ok(())
}

pub fn render_pcap(pc: &pcap::PacketCaptureView) -> Result<(), JsValue> {
    let window = web_sys::window().expect("no global `window` exists");
    let document = window.document().expect("should have a document on window");
    let body = document.body().expect("document should have a body");

    let tbl = document
        .create_element("table")?
        .dyn_into::<web_sys::HtmlTableElement>()?;

    tbl.set_id("packet-view");

    body.append_child(&tbl)?;
    let row = tbl
        .insert_row()?
        .dyn_into::<web_sys::HtmlTableRowElement>()?;
    let cell = row
        .insert_cell()?
        .dyn_into::<web_sys::HtmlTableCellElement>()?;
    cell.set_inner_text("No.");
    let cell = row
        .insert_cell()?
        .dyn_into::<web_sys::HtmlTableCellElement>()?;
    cell.set_inner_text("source");
    let cell = row
        .insert_cell()?
        .dyn_into::<web_sys::HtmlTableCellElement>()?;
    cell.set_inner_text("destination");

    for (i, pkt) in pc.records.iter().enumerate() {
        let row = tbl
            .insert_row()?
            .dyn_into::<web_sys::HtmlTableRowElement>()?;
        let cell = row
            .insert_cell()?
            .dyn_into::<web_sys::HtmlTableCellElement>()?;
        cell.set_inner_text(&format!("{}", i));

        let mut offset = 0;
        let l1 = pnet_packet::ethernet::EthernetPacket::new(&pkt.payload).unwrap();
        offset += ethernet::EthernetPacket::minimum_packet_size();

        let l2 = match l1.get_ethertype() {
            ethernet::EtherTypes::Ipv4 => {
                let ret = ipv4::Ipv4Packet::new(&pkt.payload[offset..]).unwrap();
                offset += ipv4::Ipv4Packet::minimum_packet_size();
                ret
            }
            _ => panic!(),
        };

        let l3 = match l2.get_next_level_protocol() {
            ip::IpNextHeaderProtocols::Udp => {
                let ret = udp::UdpPacket::new(&pkt.payload[offset..]).unwrap();
                offset += udp::UdpPacket::minimum_packet_size();
                ret
            }
            _ => panic!(),
        };

        let mut cur = std::io::Cursor::new(&pkt.payload[offset..]);
        let l4 = match (l3.get_source(), l3.get_destination()) {
            (53, _) | (_, 53) => ("DNS", dns::DnsPacketBuilder::parse(&cur.remaining_slice())),
            (_, _) => panic!(),
        };

        let cell = row
            .insert_cell()?
            .dyn_into::<web_sys::HtmlTableCellElement>()?;
        cell.set_inner_text(&format!("{:?}", l2.get_source()));
        let cell = row
            .insert_cell()?
            .dyn_into::<web_sys::HtmlTableCellElement>()?;
        cell.set_inner_text(&format!("{:?}", l2.get_destination()));
        let cell = row
            .insert_cell()?
            .dyn_into::<web_sys::HtmlTableCellElement>()?;
        cell.set_inner_text(&format!("{:?}", l3.get_source()));
        let cell = row
            .insert_cell()?
            .dyn_into::<web_sys::HtmlTableCellElement>()?;
        cell.set_inner_text(&format!("{:?}", l3.get_destination()));
        let cell = row
            .insert_cell()?
            .dyn_into::<web_sys::HtmlTableCellElement>()?;
        cell.set_inner_text(l4.0);
        let cell = row
            .insert_cell()?
            .dyn_into::<web_sys::HtmlTableCellElement>()?;
        cell.set_inner_text(&format!("{:?}", l4.1));
    }

    Ok(())
}

#[cfg(test)]
pub mod test {
    use pnet_packet::{ethernet, ipv4, udp};

    #[test]
    fn test_lens() {
        assert_eq!(ethernet::EthernetPacket::minimum_packet_size(), 14);
        assert_eq!(ipv4::Ipv4Packet::minimum_packet_size(), 20);
        assert_eq!(udp::UdpPacket::minimum_packet_size(), 8);
    }
}
