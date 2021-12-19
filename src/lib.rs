//use nom::{branch::alt, bytes::complete::tag, IResult};

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
    let pc = pcap::PacketCapture::new(&mut cur);
    let fv = pc.filter(query);
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

        let l1 = pnet_packet::ethernet::EthernetPacket::new(&pkt.payload).unwrap();
        let l2 = match l1.get_ethertype() {
            ethernet::EtherTypes::Ipv4 => ipv4::Ipv4Packet::new(&pkt.payload[14..]).unwrap(),
            _ => panic!(),
        };
        let l3 = match l2.get_next_level_protocol() {
            ip::IpNextHeaderProtocols::Udp => {
                udp::UdpPacket::new(&pkt.payload[(14 + 20)..]).unwrap()
            }

            _ => panic!(),
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
    }

    Ok(())
}
