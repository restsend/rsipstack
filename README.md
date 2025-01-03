# A SIP Stack written in Rust

**WIP** This is a work in progress and is not yet ready for production use.

A RFC 3261 compliant SIP stack written in Rust. The goal of this project is to provide a high-performance, reliable, and easy-to-use SIP stack that can be used in various scenarios.


## TODO
- [ ] Transport support
  - [-] UDP
  - [ ] TCP
  - [ ] TLS
  - [ ] WebSocket
- [ ] Authentication
    - [ ] Digest
    - [ ] Basic
- [x] Transaction Layer
- [ ] Dialog Layer
- [ ] WASM target


## Use Cases

This SIP stack can be used in various scenarios, including but not limited to:

- Integration with WebRTC for browser-based communication, such as WebRTC SBC.
- Building custom SIP proxies or registrars
- Building custom SIP user agents (SIP.js alternative)

## Why Rust?

We are a group of developers who are passionate about SIP and Rust. We believe that Rust is a great language for building high-performance network applications, and we want to bring the power of Rust to the SIP/WebRTC/SFU world.

