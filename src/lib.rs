//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Amora is a secure token inspired by [JWT](https://jwt.io) and [Branca](https://branca.io/),
//! but enhanced a bit in some areas.
//!
//! Key features:
//! - Can contain any type of payload: JSON, msgpack, cbor and so on...
//! - Always encrypted and authenticated using XChaCha20-Poly1305 algorithm.
//! - There are two versions of Amora:
//!     - **Amora zero**: encrypted with a 32-byte symmetric key.
//!     - **Amora one**: encrypted with a 32-byte asymmetric key.
//! - Encoded using url-safe base64.
//! - Always contain token generation time and TTL.
//!
//! ## Amora structure
//!
//! - header (4 bytes for Amora zero; 36 bytes for Amora one):
//!     - version marker: 0xa0 or 0xa1 (1 byte)
//!     - TTL (3 bytes; little-endian)
//!     - randomly generated public key (32 bytes; Amora one only)
//! - nonce (24 bytes)
//!     - token generation time (first 4 bytes; little-endian)
//!     - randomly generated 20 bytes
//! - payload (any length)
//! - message authentication code (4 bytes)
//!
//! ## Token generation time (TGT) + TTL
//!
//! TGT is an unsigned 32-bit int. It's a number of seconds starting from the Unix epoch
//! on January 1, 1970 UTC. This means that Amora tokens will work correctly until the year 2106.
//!
//! TTL is an unsigned 24-bits int. It means that each token can be valid for a maximum of 194 days.
//!
//! ## Asymmetric encryption
//!
//! The shared key is computed using the X25519 function. It requires two pairs of priv/pub keys.
//! The first pair must be known. The second pair is randomly generated for each token.

use base64::{Engine, engine::general_purpose};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use generic_array::GenericArray;
use rand_core::{RngCore, OsRng};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

#[derive(Clone, Copy)]
enum AmoraVer {
	Zero = 0xa0,
	One = 0xa1,
}

pub struct Amora {
	version: AmoraVer,
	cipher: Option<XChaCha20Poly1305>,
	secret_key: Option<StaticSecret>,
	public_key: Option<PublicKey>,
}

impl Amora {
	/// Creates Amora instance with a symmetric key loaded from [u8; 32] slice.
	/// ```rust
	/// let key = [
	///     0x4f, 0x99, 0x70, 0x66, 0x2f, 0xac, 0xd3, 0x7d,
	///     0xc3, 0x6c, 0x0f, 0xd1, 0xda, 0xd0, 0x7e, 0xaa,
	///     0x04, 0x7c, 0x28, 0x54, 0x58, 0x3c, 0x92, 0x0f,
	///     0x52, 0x4b, 0x2b, 0x01, 0xd8, 0x40, 0x83, 0x1a,
	/// ];
	/// let amora = Amora::amora_zero(&key);
	/// ```
	pub fn amora_zero(key: &[u8; 32]) -> Amora {
		Amora {
			version: AmoraVer::Zero,
			cipher: XChaCha20Poly1305::new_from_slice(key).ok(),
			secret_key: None,
			public_key: None,
		}
	}

	/// Creates Amora instance with an asymmetric key loaded from two [u8; 32] slices.
	/// ```rust
	/// let secret_key = StaticSecret::random();
	/// let public_key = PublicKey::from(&secret_key);
	/// let amora = Amora::amora_one(Some(secret_key), Some(public_key));
	/// ```
	/// The public key is used to encrypt the token,
	/// and the private key is used to decrypt the token.
	/// One of these keys can be None when not in use.
	pub fn amora_one(secret_key: Option<StaticSecret>, public_key: Option<PublicKey>) -> Amora {
		Amora {
			version: AmoraVer::One,
			cipher: None,
			secret_key,
			public_key,
		}
	}

	fn key_from_str(key: &str) -> Result<[u8; 32], AmoraErr> {
		if key.len() != 64 {
			return Err(AmoraErr::InvalidKey);
		}

		let mut key_bytes = [0u8; 32];

		#[allow(clippy::needless_range_loop)]
		for i in 0 .. 32 {
			let a = i * 2;
			let e = a + 2;
			if let Ok(byte) = u8::from_str_radix(&key[a .. e], 16) {
				key_bytes[i] = byte;
			} else {
				return Err(AmoraErr::InvalidKey);
			}
		}

		Ok(key_bytes)
	}

	/// Creates Amora instance with a symmetric key loaded from a hex string.
	/// ```rust
	/// let key = "4f9970662facd37dc36c0fd1dad07eaa047c2854583c920f524b2b01d840831a";
	/// let amora = Amora::amora_zero_from_str(key).unwrap();
	/// ```
	pub fn amora_zero_from_str(key: &str) -> Result<Amora, AmoraErr> {
		let key = Self::key_from_str(key)?;
		Ok(Self::amora_zero(&key))
	}

	/// Create Amora instance with an asymmetric key loaded from two strings.
	/// ```rust
	/// let secret_key = "778d0b92672b9a25ec4fbe65e3ad2212efa011e8f7035754c1342fe46191dbb3";
	/// let public_key = "5cdd89c1bb6859c927c50b6976712f256cdbf14d7273f723dc121c191f9d6d6d";
	/// let amora = Amora::amora_one_from_str(Some(secret_key), Some(public_key)).unwrap();
	/// ```
	/// The public key is used to encrypt the token,
	/// and the private key is used to decrypt the token.
	/// One of these keys can be None when not in use.
	pub fn amora_one_from_str(secret_key: Option<&str>, public_key: Option<&str>)
		-> Result<Amora, AmoraErr> {

		let secret_key = match secret_key {
			Some(key) => {
				let key = Self::key_from_str(key)?;
				Some(key.into())
			},
			None => None,
		};

		let public_key = match public_key {
			Some(key) => {
				let key = Self::key_from_str(key)?;
				Some(key.into())
			},
			None => None,
		};

		Ok(Self::amora_one(secret_key, public_key))
	}

	fn aad_len(&self) -> usize {
		match &self.version {
			AmoraVer::Zero => 4,
			AmoraVer::One => 36,
		}
	}

	/// Encodes the token.
	/// TTL is the number of seconds that the token will be valid for.
	/// ```rust
	/// let payload = "sample_payload";
	/// let token = amora.encode(&payload.as_bytes(), 1800);
	/// ```
	pub fn encode(&self, payload: &[u8], ttl: u32) -> String {
		let (cipher, rand_public_key) = match &self.version {
			AmoraVer::Zero => {
				(self.cipher.clone().unwrap(), None)
			},
			AmoraVer::One => {
				let rand_secret_key = EphemeralSecret::random();
				let rand_public_key = PublicKey::from(&rand_secret_key);
				let shared_key = rand_secret_key
					.diffie_hellman(&self.public_key.unwrap());
				let cipher = XChaCha20Poly1305
					::new_from_slice(shared_key.as_bytes()).unwrap();
				(cipher, Some(rand_public_key))
			},
		};

		let aad_len = self.aad_len();
		let mut aad = Vec::with_capacity(aad_len);
		aad.push(self.version as u8);
		aad.extend_from_slice(&ttl.to_le_bytes()[..3]);
		if let Some(rand_public_key) = rand_public_key {
			aad.extend_from_slice(rand_public_key.as_bytes());
		}

		let mut nonce = Vec::with_capacity(24);
		let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
		nonce.extend_from_slice(&now.to_le_bytes()[..4]);
		let mut randbuf = [0u8; 20];
		OsRng.fill_bytes(&mut randbuf);
		nonce.extend_from_slice(&randbuf);
		let nonce_ga = GenericArray::from_slice(&nonce);

		let pt_aad = Payload { msg: payload, aad: &aad };
		let mut ct = cipher.encrypt(nonce_ga, pt_aad).unwrap();

		let mut token = Vec::with_capacity(aad_len + 24 + ct.len());
		token.append(&mut aad);
		token.append(&mut nonce);
		token.append(&mut ct);

		general_purpose::URL_SAFE_NO_PAD.encode(token)
	}

	/// Decodes the token.
	/// TTL is only validated if the validate flag is true.
	/// ```rust
	/// let payload = amora.decode(&token, true).unwrap_or("".into());
	/// let payload = std::str::from_utf8(&payload).unwrap_or("");
	/// ```
	pub fn decode(&self, token: &str, validate: bool) -> Result<Vec<u8>, AmoraErr> {
		let token = match general_purpose::URL_SAFE_NO_PAD.decode(token) {
			Ok(token) => token,
			Err(_) => return Err(AmoraErr::WrongEncoding),
		};

		if token[0] != self.version as u8 {
			return Err(AmoraErr::UnsupportedVersion);
		}

		let aad_len = self.aad_len();
		let aad = &token[.. aad_len];
		let nonce = GenericArray::from_slice(&token[aad_len .. aad_len+24]);
		let ct = &token[aad_len+24 ..];

		if validate {
			let ttl = u32::from_le_bytes(aad[..4].try_into().unwrap()) >> 8;
			let timestamp = u32::from_le_bytes(nonce[..4].try_into().unwrap());
			let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
			if u64::from(timestamp + ttl) < now {
				return Err(AmoraErr::ExpiredToken);
			}
		}

		let cipher = match &self.version {
			AmoraVer::Zero => {
				self.cipher.clone().unwrap()
			},
			AmoraVer::One => {
				let rand_public_key: [u8; 32] = aad[4..].try_into().unwrap();
				let rand_public_key = PublicKey::from(rand_public_key);
				let shared_key = self.secret_key.as_ref().unwrap()
					.diffie_hellman(&rand_public_key);
				XChaCha20Poly1305::new_from_slice(shared_key.as_bytes()).unwrap()
			},
		};

		let ct_aad = Payload { msg: ct, aad };
		match cipher.decrypt(nonce, ct_aad) {
			Ok(payload) => Ok(payload),
			Err(_) => Err(AmoraErr::EncryptionError),
		}
	}
}

#[derive(Debug)]
pub enum AmoraErr {
	InvalidKey,
	WrongEncoding,
	UnsupportedVersion,
	ExpiredToken,
	EncryptionError,
}

#[cfg(test)]
mod tests;
