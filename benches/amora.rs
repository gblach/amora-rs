use amora_rs::Amora;
use x25519_dalek::{PublicKey, StaticSecret};

fn criterion_benchmark(c: &mut criterion::Criterion) {
	c.bench_function("amora_zero", |b| b.iter(|| {
		let key = [
			0x4f, 0x99, 0x70, 0x66, 0x2f, 0xac, 0xd3, 0x7d,
			0xc3, 0x6c, 0x0f, 0xd1, 0xda, 0xd0, 0x7e, 0xaa,
			0x04, 0x7c, 0x28, 0x54, 0x58, 0x3c, 0x92, 0x0f,
			0x52, 0x4b, 0x2b, 0x01, 0xd8, 0x40, 0x83, 0x1a,
		];
		let amora = Amora::amora_zero(&key);
		let payload = "sample_payload_just_for_benchmarking";
		let token = amora.encode(&payload.as_bytes(), 1);
		let _ = amora.decode(&token, true).unwrap_or("".into());
	}));

	c.bench_function("amora_zero_from_str", |b| b.iter(|| {
		let key = "4f9970662facd37dc36c0fd1dad07eaa047c2854583c920f524b2b01d840831a";
		let _ = Amora::amora_zero_from_str(key).unwrap();
	}));

	c.bench_function("amora_one", |b| b.iter(|| {
		let secret_key = StaticSecret::random();
		let public_key = PublicKey::from(&secret_key);
		let amora = Amora::amora_one(Some(secret_key), Some(public_key));
		let payload = "sample_payload_just_for_benchmarking";
		let token = amora.encode(&payload.as_bytes(), 1);
		let _ = amora.decode(&token, true).unwrap_or("".into());
	}));
}

criterion::criterion_group!(benches, criterion_benchmark);
criterion::criterion_main!(benches);
