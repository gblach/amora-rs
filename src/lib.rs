//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.

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
	pub fn amora_zero(key: &[u8; 32]) -> Amora {
		Amora {
			version: AmoraVer::Zero,
			cipher: XChaCha20Poly1305::new_from_slice(key).ok(),
			secret_key: None,
			public_key: None,
		}
	}

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

	pub fn amora_zero_from_str(key: &str) -> Result<Amora, AmoraErr> {
		let key = Self::key_from_str(key)?;
		Ok(Self::amora_zero(&key))
	}

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
