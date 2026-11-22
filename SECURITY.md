# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.8.x   | Yes       |
| 0.7.15+ | Yes       |
| 0.7.14 and earlier | No |
| < 0.7   | No        |

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/restsend/rsipstack/security/advisories/new).
Do not open a public issue for an unfixed vulnerability.

We aim to acknowledge a report within 7 days and to ship a fix or mitigation
within 90 days. We will coordinate the disclosure date with the reporter and
credit them in the advisory unless they prefer otherwise.

## Published advisories

### SIP stream framing: unchecked Content-Length

- Advisory: [GHSA-6xf4-56fp-45wq](https://github.com/restsend/rsipstack/security/advisories/GHSA-6xf4-56fp-45wq)
- CVE: requested (pending assignment)
- Affected: `>= 0.2.66, < 0.8.0`
- Patched: `0.8.0`, `0.7.15`
- Reported by: Matt Harrison (MSH)
- Published: 2026-11

The stream transport (`src/transport/stream.rs`) parsed the peer-supplied
`Content-Length` into `usize` without an upper bound and added it to the
header offset with unchecked arithmetic. The `MAX_SIP_MESSAGE_SIZE` check ran
only after that branch, so it did not guard the addition. Any peer able to
reach a TCP, TLS or WebSocket SIP listener could therefore:

- panic the connection task, and possibly the process, in debug builds or any
  build with `overflow-checks = true`, using a value such as
  `Content-Length: 18446744073709551615`; or
- in release builds, wrap the total length, split the buffer inside the header
  block, and desynchronise framing so that peer-controlled bytes are parsed as
  the start of a new SIP message (a request-smuggling primitive).

Fixed in 0.8.0 (commit `13abad6`) and backported to 0.7.15. The length
addition now uses checked arithmetic, and any declared body that would make
the message exceed `MAX_SIP_MESSAGE_SIZE` is rejected before the connection
buffers towards it. Duplicate `Content-Length`/`l` headers are also rejected.
Regression tests cover `usize::MAX`, the decimal value from the report, an
oversized declared body, duplicate headers, and pipelined-message alignment.

Users on 0.7.x should upgrade to 0.7.15 or later; users on 0.8.x are already
fixed.
