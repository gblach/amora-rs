use super::*;

#[test]
fn symmetric_new() {
	let key = [
		0x4f, 0x99, 0x70, 0x66, 0x2f, 0xac, 0xd3, 0x7d,
		0xc3, 0x6c, 0x0f, 0xd1, 0xda, 0xd0, 0x7e, 0xaa,
		0x04, 0x7c, 0x28, 0x54, 0x58, 0x3c, 0x92, 0x0f,
		0x52, 0x4b, 0x2b, 0x01, 0xd8, 0x40, 0x83, 0x1a,
	];
	let amora = Amora::amora_zero(&key);
	let payload = "sample_payload_just_for_testing";
	let token = amora.encode(&payload.as_bytes(), 1);
	let decoded = amora.decode(&token, true).unwrap_or("".into());
	let decoded = std::str::from_utf8(&decoded).unwrap_or("");
	assert_eq!(payload, decoded);
}

#[test]
fn symmetric_from_str() {
	let key = "4f9970662facd37dc36c0fd1dad07eaa047c2854583c920f524b2b01d840831a";
	let amora = Amora::amora_zero_from_str(key).unwrap();
	let payload = "sample_payload_just_for_testing";
	let token = amora.encode(&payload.as_bytes(), 1);
	let decoded = amora.decode(&token, true).unwrap_or("".into());
	let decoded = std::str::from_utf8(&decoded).unwrap_or("");
	assert_eq!(payload, decoded);
}

#[test]
fn symmetric_two_keys() {
	let key = [
		0x4f, 0x99, 0x70, 0x66, 0x2f, 0xac, 0xd3, 0x7d,
		0xc3, 0x6c, 0x0f, 0xd1, 0xda, 0xd0, 0x7e, 0xaa,
		0x04, 0x7c, 0x28, 0x54, 0x58, 0x3c, 0x92, 0x0f,
		0x52, 0x4b, 0x2b, 0x01, 0xd8, 0x40, 0x83, 0x1a,
	];
	let amora = Amora::amora_zero(&key);
	let payload = "sample_payload_just_for_testing";
	let token = amora.encode(&payload.as_bytes(), 1);
	let key = "4f9970662facd37dc36c0fd1dad07eaa047c2854583c920f524b2b01d840831a";
	let amora = Amora::amora_zero_from_str(key).unwrap();
	let decoded = amora.decode(&token, true).unwrap_or("".into());
	let decoded = std::str::from_utf8(&decoded).unwrap_or("");
	assert_eq!(payload, decoded);
}

#[test]
fn symmetric_key_invalid_chars() {
	let key = "ZXCV70662facd37dc36c0fd1dad07eaa047c2854583c920f524b2b01d840831a";
	let amora = Amora::amora_zero_from_str(key);
	assert!(amora.is_err());
}

#[test]
fn symmetric_key_too_short() {
	let key = "4f99";
	let amora = Amora::amora_zero_from_str(key);
	assert!(amora.is_err());
}

#[test]
fn symmetric_key_too_long() {
	let key = "4f9970662facd37dc36c0fd1dad07eaa047c2854583c920f524b2b01d840831a01234";
	let amora = Amora::amora_zero_from_str(key);
	assert!(amora.is_err());
}

#[test]
fn asymmetric_new() {
	let secret_key = StaticSecret::random();
	let public_key = PublicKey::from(&secret_key);
	let amora = Amora::amora_one(Some(secret_key), Some(public_key));
	let payload = "sample_payload_just_for_testing";
	let token = amora.encode(&payload.as_bytes(), 1);
	let decoded = amora.decode(&token, true).unwrap_or("".into());
	let decoded = std::str::from_utf8(&decoded).unwrap_or("");
	assert_eq!(payload, decoded);
}

#[test]
fn asymmetric_from_str() {
	let secret_key = "778d0b92672b9a25ec4fbe65e3ad2212efa011e8f7035754c1342fe46191dbb3";
	let public_key = "5cdd89c1bb6859c927c50b6976712f256cdbf14d7273f723dc121c191f9d6d6d";
	let amora = Amora::amora_one_from_str(Some(secret_key), Some(public_key)).unwrap();
	let payload = "sample_payload_just_for_testing";
	let token = amora.encode(&payload.as_bytes(), 1);
	let decoded = amora.decode(&token, true).unwrap_or("".into());
	let decoded = std::str::from_utf8(&decoded).unwrap_or("");
	assert_eq!(payload, decoded);
}

#[test]
fn asymmetric_encode_only() {
	let public_key = "5cdd89c1bb6859c927c50b6976712f256cdbf14d7273f723dc121c191f9d6d6d";
	let amora = Amora::amora_one_from_str(None, Some(public_key)).unwrap();
	let payload = "sample_payload_just_for_testing";
	let token = amora.encode(&payload.as_bytes(), 1);
	assert_eq!(token.len(), 143);
}

#[test]
fn asymmetric_decode_only() {
	let secret_key = "778d0b92672b9a25ec4fbe65e3ad2212efa011e8f7035754c1342fe46191dbb3";
	let amora = Amora::amora_one_from_str(Some(secret_key), None).unwrap();
	let payload = "sample_payload_just_for_testing";
	let token = concat!("oQEAAGgmXpFevpAoQpgcC7AFgwmbHKDTABRGdPQxfsIymRJPN4VWZdALbFb_E3Jd8_",
		"xGAihaJSerdTCt-zpa0XRS-sY5F4H1SZ5mwRzpWc4rXYMY1NIgz8DpsGTD-JAdqmsIgTo6SRYl4m4");
	let decoded = amora.decode(&token, false).unwrap_or("".into());
	let decoded = std::str::from_utf8(&decoded).unwrap_or("");
	assert_eq!(payload, decoded);
}
