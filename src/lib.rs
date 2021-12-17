//use nom::{branch::alt, bytes::complete::tag, IResult};

pub mod pcap;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

#[wasm_bindgen]
extern "C" {
    pub fn alert(s: &str);
}

#[wasm_bindgen]
pub fn render_pcap(data: &[u8]) -> Result<(), JsValue> {
    let mut cur = std::io::Cursor::new(data);
    let pc = pcap::PacketCapture::new(&mut cur);
    alert(&format!("parsed: {}, pkts", pc.len()));

    let window = web_sys::window().expect("no global `window` exists");
    let document = window.document().expect("should have a document on window");
    let body = document.body().expect("document should have a body");

    let tbl = document
        .create_element("table")?
        .dyn_into::<web_sys::HtmlTableElement>()?;

    body.append_child(&tbl)?;

    for i in 0..pc.len() {
        let row = tbl
            .insert_row()?
            .dyn_into::<web_sys::HtmlTableRowElement>()?;
        let cell = row
            .insert_cell()?
            .dyn_into::<web_sys::HtmlTableCellElement>()?;
        cell.set_inner_text(&format!("pkt {}", i));
    }

    Ok(())
}
