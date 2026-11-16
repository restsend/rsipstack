//! Regression tests for issue #258: typed header and URI parsers must reject
//! text outside the RFC 3261 grammar, and printing a parsed value must produce
//! text that parses again (parse → print → parse is stable).

use rsipstack::sip::{parse_uri, typed::*};

#[test]
fn stray_angle_bracket_in_addr_spec_is_rejected() {
    // '>' inside an addr-spec without angle brackets used to be accepted and
    // printed inside <...>, producing output that failed to re-parse.
    assert!(To::parse("sip:bob@example.com>x").is_err());
    assert!(Contact::parse("sip:bob@example.com>x").is_err());
    assert!(Route::parse("sip:bob@example.com>x").is_err());
    assert!(RecordRoute::parse("sip:bob@example.com>x").is_err());
    assert!(ServiceRoute::parse("sip:bob@example.com>x").is_err());
    assert!(Diversion::parse("<sip:bob@example.com>x>;reason=no-answer").is_err());
    assert!(parse_uri("sip:bob@example.com>x").is_err());
}

#[test]
fn stray_quote_in_unquoted_auth_param_is_rejected() {
    // A '"' inside an unquoted auth-param value used to be accepted and then
    // printed inside quotes, producing `realm="a"b"` which does not re-parse.
    assert!(WwwAuthenticate::parse(r#"Digest realm=a"b, nonce="n1""#).is_err());
    assert!(ProxyAuthenticate::parse(r#"Digest realm=a"b, nonce="n1""#).is_err());
    assert!(Authorization::parse(
        r#"Digest username=a"b, realm="x", nonce="n", uri="sip:u@h", response="r""#
    )
    .is_err());
    // Same for header/URI params: an unquoted value must be a token.
    assert!(To::parse(r#"<sip:alice@example.com>;tag=a"b"#).is_err());
}

#[test]
fn quoted_pairs_in_challenges_round_trip() {
    // The converse used to fail: a valid quoted-pair in a quoted realm
    // (RFC 3261 section 25.1) was rejected on parse.
    for raw in [
        r#"Digest realm="a\"b", nonce="n1""#,
        r#"Digest realm="a\\b", nonce="n1""#,
    ] {
        let challenge = WwwAuthenticate::parse(raw).unwrap();
        assert_eq!(
            challenge.to_string(),
            raw,
            "first print differs for {:?}",
            raw
        );
        let reparsed = WwwAuthenticate::parse(&challenge.to_string()).unwrap();
        assert_eq!(reparsed, challenge);
    }

    let auth = Authorization::parse(
        r#"Digest username="a\"b", realm="x", nonce="n", uri="sip:u@h", response="r""#,
    )
    .unwrap();
    assert_eq!(auth.username, "a\"b");
    assert!(Authorization::parse(&auth.to_string()).is_ok());
}

#[test]
fn port_must_not_silently_disappear() {
    // A port made only of whitespace used to be read as no port while the ':'
    // stayed in the domain, so the URI printed as `host:` and stopped parsing.
    assert!(parse_uri("sip:host: ;tag=x").is_err());
    assert!(parse_uri("sip:host:").is_err());
    assert!(parse_uri("sip:host:5060;tag=x").is_ok());
}

#[test]
fn non_uri_text_is_rejected() {
    // `parse_uri` used to accept text that is not a URI and print it
    // differently on each parse/print cycle.
    assert!(parse_uri("ih./\u{3}<sip:alice;tranAsport=tcp>;").is_err());
}

#[test]
fn control_characters_in_header_values_are_rejected() {
    assert!(To::parse("sip:bob@example.com;tag=a\u{7}b").is_err());
    assert!(Contact::parse("sip:bob@example.com>x\u{1}").is_err());
    assert!(WwwAuthenticate::parse("Digest realm=a\u{7}b, nonce=n").is_err());
}

#[test]
fn parse_print_parse_is_idempotent_for_typed_headers() {
    let to_cases = [
        "\"Alice Smith\" <sip:alice@example.com>",
        "<sip:alice@example.com>;tag=xyz",
        "<sip:alice@example.com>;tag=\"a\\\"b\"",
    ];
    for raw in to_cases {
        let header = To::parse(raw).unwrap_or_else(|e| panic!("{:?} should parse: {}", raw, e));
        let printed = header.to_string();
        let reparsed =
            To::parse(&printed).unwrap_or_else(|e| panic!("{:?} should re-parse: {}", printed, e));
        assert_eq!(
            reparsed.to_string(),
            printed,
            "unstable round trip for {:?}",
            raw
        );
    }

    let route_cases = [
        "<sip:proxy.example.com;lr>",
        "\"Edge Proxy\" <sip:edge.example.com;transport=tls>",
    ];
    for raw in route_cases {
        let header = Route::parse(raw).unwrap();
        let printed = header.to_string();
        let reparsed = Route::parse(&printed)
            .unwrap_or_else(|e| panic!("{:?} should re-parse: {}", printed, e));
        assert_eq!(
            reparsed.to_string(),
            printed,
            "unstable round trip for {:?}",
            raw
        );
    }
}

#[test]
fn lenient_inputs_that_must_keep_working_still_do() {
    // Real-world inputs the stricter grammar must not break.
    assert!(Contact::parse("*").is_ok());
    assert!(parse_uri("tel:+1-201-555-0123").is_ok());
    assert!(parse_uri("sip:alice@_sip._udp.example.com").is_ok());
    assert!(WwwAuthenticate::parse(
        "Digest realm=example.com, nonce=MTM3MzAzNDQyNDo3OGM3MTczNmE6YjE1Zg==, stale=TRUE, algorithm=MD5"
    )
    .is_ok());
    let header = r#"Digest username="111",realm="pbx.e36",nonce="abc",uri="sip:pbx.e36:5061;transport=tls",response="xxx",algorithm=MD5"#;
    let auth = Authorization::parse(header).unwrap();
    assert_eq!(auth.username, "111");
}
