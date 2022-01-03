pub mod dns;
pub mod pcap;

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

    use pcap::Fields;
    let cols = vec![
        Fields::SrcIpAddr(),
        Fields::DstIpAddr(),
        Fields::L4Src(),
        Fields::L4Dst(),
        Fields::Protocol(),
        Fields::Info(),
    ];

    for f in &cols {
        let cell = row
            .insert_cell()?
            .dyn_into::<web_sys::HtmlTableCellElement>()?;
        cell.set_inner_text(f.name());
    }

    for pkt in pc.records.iter() {
        let row = tbl
            .insert_row()?
            .dyn_into::<web_sys::HtmlTableRowElement>()?;
        for f in &cols {
            let pr = pcap::ParsedRecord::new(pkt);
            let cell = row
                .insert_cell()?
                .dyn_into::<web_sys::HtmlTableCellElement>()?;
            cell.set_inner_text(&pr.get_field(f).unwrap_or_else(|| "".to_owned()));
        }
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
