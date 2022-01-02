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

## Useful reading
- [pcap file format](https://wiki.wireshark.org/Development/LibpcapFileFormat)
- [dns implementation rfc](https://datatracker.ietf.org/doc/html/rfc1035)
