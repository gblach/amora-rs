# Amora

Amora is a secure token inspired by [JWT](https://jwt.io) and [Branca](https://branca.io/),
but enhanced a bit in some areas.

Key features:
- Can contain any type of payload: JSON, msgpack, cbor and so on...
- Always encrypted and authenticated using XChaCha20-Poly1305 algorithm.
- There are two versions of Amora:
	- **Amora zero**: encrypted with a 32-byte symmetric key.
	- **Amora one**: encrypted with a 32-byte asymmetric key.
- Encoded using url-safe base64.
- Always contain token generation time and TTL.

## Amora structure

- header (4 bytes for Amora zero; 36 bytes for Amora one):
	- version marker: 0xa0 or 0xa1 (1 byte)
	- TTL (3 bytes; little-endian)
	- randomly generated public key (32 bytes; Amora one only)
- nonce (24 bytes)
	- token generation time (first 4 bytes; little-endian)
	- randomly generated 20 bytes
- payload (any length)
- message authentication code (4 bytes)

## Token generation time (TGT) + TTL

TGT is an unsigned 32-bit int. It's a number of seconds starting from the Unix epoch
on January 1, 1970 UTC. This means that Amora tokens will work correctly until the year 2106.

TTL is an unsigned 24-bits int. It means that each token can be valid for a maximum of 194 days.

## Asymmetric encryption

The shared key is computed using the X25519 function. It requires two pairs of priv/pub keys.
The first pair must be known. The second pair is randomly generated for each token.

## Code examples

### Symmetric key from bytes

```rust
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
```

### Symmetric key from string

```rust
let key = "4f9970662facd37dc36c0fd1dad07eaa047c2854583c920f524b2b01d840831a";
let amora = Amora::amora_zero_from_str(key).unwrap();
let payload = "sample_payload_just_for_testing";
let token = amora.encode(&payload.as_bytes(), 1);
let decoded = amora.decode(&token, true).unwrap_or("".into());
let decoded = std::str::from_utf8(&decoded).unwrap_or("");
```

### Asymmetric key from bytes

```rust
let secret_key = StaticSecret::random();
let public_key = PublicKey::from(&secret_key);
let amora = Amora::amora_one(Some(secret_key), Some(public_key));
let payload = "sample_payload_just_for_testing";
let token = amora.encode(&payload.as_bytes(), 1);
let decoded = amora.decode(&token, true).unwrap_or("".into());
let decoded = std::str::from_utf8(&decoded).unwrap_or("");
```

### Asymmetric key from string

```rust
let secret_key = "778d0b92672b9a25ec4fbe65e3ad2212efa011e8f7035754c1342fe46191dbb3";
let public_key = "5cdd89c1bb6859c927c50b6976712f256cdbf14d7273f723dc121c191f9d6d6d";
let amora = Amora::amora_one_from_str(Some(secret_key), Some(public_key)).unwrap();
let payload = "sample_payload_just_for_testing";
let token = amora.encode(&payload.as_bytes(), 1);
let decoded = amora.decode(&token, true).unwrap_or("".into());
let decoded = std::str::from_utf8(&decoded).unwrap_or("");
```
