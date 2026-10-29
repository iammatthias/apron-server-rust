use super::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn unmarshal_rejects_trailing_data() {
    // webauthncbor_test.go TestUnmarshalRejectsTrailingData.
    assert_eq!(
        unmarshal(&hex("a16161010102")).unwrap_err().to_string(),
        "cbor: 2 bytes of extraneous data starting at index 4"
    );
    assert_eq!(
        unmarshal(&hex("01ff")).unwrap_err().to_string(),
        "cbor: 1 bytes of extraneous data starting at index 1"
    );
}

#[test]
fn unmarshal_first_accepts_trailing_data() {
    // webauthncbor_test.go TestUnmarshalFirstAcceptsTrailingData.
    let (value, n) = unmarshal_first(&hex("a161610100")).unwrap();
    assert_eq!(n, 4);
    assert_eq!(
        value,
        Value::Map(vec![(Value::Text("a".into()), Value::Unsigned(1))])
    );
}

#[test]
fn limits() {
    let cases: &[(&str, &str)] = &[
        ("", "EOF"),
        ("18", "unexpected EOF"),
        ("62ff", "unexpected EOF"),
        ("bf61610100ff", "cbor: indefinite-length map isn't allowed"),
        ("9fff", "cbor: indefinite-length array isn't allowed"),
        (
            "5f4100ff",
            "cbor: indefinite-length byte string isn't allowed",
        ),
        (
            "7f6161ff",
            "cbor: indefinite-length UTF-8 text string isn't allowed",
        ),
        ("c11a514b67b0", "cbor: CBOR tag isn't allowed"),
        ("81818181818101", "cbor: exceeded max nested level 5"),
        ("f810", "cbor: invalid simple value 16 for type primitives"),
        (
            "1c",
            "cbor: invalid additional information 28 for type positive integer",
        ),
        (
            "1f",
            "cbor: invalid additional information 31 for type positive integer",
        ),
        ("ff", "cbor: unexpected \"break\" code"),
        (
            "9b0000000000020001",
            "cbor: exceeded max number of elements 131072 for CBOR array",
        ),
        (
            "bb0000000000020001",
            "cbor: exceeded max number of key-value pairs 131072 for CBOR map",
        ),
        ("62c328", "cbor: invalid UTF-8 string"),
        (
            "a201020103",
            "cbor: found duplicate map key 0x1 at map element index 1",
        ),
        (
            "a22001380001",
            "cbor: found duplicate map key -1 at map element index 1",
        ),
        (
            "a2f93c00f6fb3ff0000000000000f6",
            "cbor: found duplicate map key 1 at map element index 1",
        ),
        ("a1810102", "cbor: invalid map key type: []interface {}"),
    ];
    for (input, want) in cases {
        assert_eq!(
            unmarshal(&hex(input)).unwrap_err().to_string(),
            *want,
            "{input}"
        );
    }
    assert!(unmarshal(&hex("818181818101")).is_ok());
    assert_eq!(unmarshal(&hex("f7")).unwrap(), Value::Null);
    assert_eq!(unmarshal(&hex("f0")).unwrap(), Value::Simple(16));
    assert_eq!(unmarshal(&hex("f8ff")).unwrap(), Value::Simple(255));
    assert_eq!(unmarshal(&hex("f93e00")).unwrap(), Value::Float(1.5));
    assert_eq!(
        unmarshal(&hex("f90001")).unwrap(),
        Value::Float(5.960464477539063e-8)
    );
    assert_eq!(
        unmarshal(&hex("f9fc00")).unwrap(),
        Value::Float(f64::NEG_INFINITY)
    );
    assert_eq!(
        unmarshal(&hex("fa47c35000")).unwrap(),
        Value::Float(100000.0)
    );
    assert_eq!(
        unmarshal(&hex("3bffffffffffffffff")).unwrap(),
        Value::Negative(u64::MAX)
    );
}

#[test]
fn marshal_is_ctap2_canonical() {
    let value = unmarshal(&hex("a5200103262201180102f93c00f6")).unwrap();
    assert_eq!(
        marshal(&value),
        hex("a50102032620012201fb3ff0000000000000f6")
    );
    let value = unmarshal(&hex("a3626161016162020180")).unwrap();
    assert_eq!(marshal(&value), hex("a3018061620262616101"));
    assert_eq!(marshal(&Value::Unsigned(1_000_000)), hex("1a000f4240"));
    assert_eq!(marshal(&Value::Negative(255)), hex("38ff"));
    assert_eq!(marshal(&Value::Null), hex("f6"));
}

#[test]
fn struct_decoding() {
    const FIELDS: &[Field] = &[
        Field {
            key: FieldKey::Name("authData"),
            kind: FieldKind::ByteSlice,
        },
        Field {
            key: FieldKey::Name("fmt"),
            kind: FieldKind::String,
        },
        Field {
            key: FieldKey::Name("attStmt"),
            kind: FieldKind::Raw,
        },
    ];
    let decode = |input: &str| {
        let data = hex(input);
        let item = parse(&data).unwrap();
        decode_struct(&item, "protocol.attestationObjectEncoded", FIELDS)
            .map(|v| format!("{v:?}"))
            .map_err(|e| e.to_string())
    };
    assert_eq!(
        decode("a363666d74646e6f6e656761747453746d74a068617574684461746141ff").unwrap(),
        r#"[Bytes([255]), String("none"), Raw([160])]"#
    );
    assert_eq!(
        decode("a263464d54646e6f6e65684155544844415441f6").unwrap(),
        r#"[Absent, String("none"), Absent]"#
    );
    assert_eq!(
        decode("a263666d74616163464d546162").unwrap_err(),
        "cbor: found duplicate map key \"FMT\" at map element index 1"
    );
    assert_eq!(decode("a2010202f6").unwrap(), "[Absent, Absent, Absent]");
    assert_eq!(
        decode("a201020103").unwrap_err(),
        "cbor: found duplicate map key 1 at map element index 1"
    );
    assert_eq!(
        decode("a163666d744161").unwrap_err(),
        "cbor: cannot unmarshal byte string into Go struct field protocol.attestationObjectEncoded.fmt of type string"
    );
    assert_eq!(
        decode("a1410101").unwrap_err(),
        "cbor: cannot unmarshal byte string into Go value of type string (map key is of type byte string and cannot be used to match struct field name)"
    );
    assert_eq!(
        decode("80").unwrap_err(),
        "cbor: cannot unmarshal array into Go value of type protocol.attestationObjectEncoded (cannot decode CBOR array to struct without toarray option)"
    );
    assert_eq!(decode("f6").unwrap(), "[Absent, Absent, Absent]");
}
