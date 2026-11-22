# Changelog

## 0.7.15

Security release. SIP stream framing (TCP, TLS and WebSocket) now rejects a
`Content-Length` that would overflow the message length or declare a body
larger than `MAX_SIP_MESSAGE_SIZE`, instead of panicking in debug builds or
wrapping in release builds and desynchronising the connection. Duplicate
`Content-Length`/`l` headers are rejected as ambiguous framing. This is a
backport of the 0.8.0 framing fix (`13abad6`); see `SECURITY.md` for the
advisory and affected versions.
