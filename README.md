# webshark
Wireshark like pcap viewer implementing in browser with rust and wasm.

## Roadmap
- [ ] filtering (src == foo && tcp.syn)
  - [ ] implement bpf virtual machine?
- [ ] packet disecting (tcp, udp, dns, http, ...)
- [ ] pcap summaries (protocols, proportions, hosts)
- [ ] timestamps
- [ ] pcap editing
  - [ ] Abilitty to change src / dst in order to make pcaps for trafgen/t-rex
