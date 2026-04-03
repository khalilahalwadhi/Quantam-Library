use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use fast_core::{FastCipher, FastCipherState, FastKey, Domain, SecurityLevel};
use fast_ff1::Ff1Cipher;

fn bench_fast_encrypt(c: &mut Criterion) {
    let key = FastKey::new(&[0x42u8; 16]).unwrap();

    let mut group = c.benchmark_group("fast-encrypt");

    // 9-digit decimal (SSN)
    let cipher = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Quantum128).unwrap();
    group.bench_function("decimal-9-q128", |b| {
        b.iter(|| cipher.encrypt(black_box(b"tweak"), black_box("123456789")).unwrap());
    });

    // 10-digit decimal
    group.bench_function("decimal-10-q128", |b| {
        b.iter(|| cipher.encrypt(black_box(b"tweak"), black_box("1234567890")).unwrap());
    });

    // 16-digit decimal (full PAN)
    group.bench_function("decimal-16-q128", |b| {
        b.iter(|| cipher.encrypt(black_box(b"tweak"), black_box("1234567890123456")).unwrap());
    });

    // Alphanumeric 8-char
    let alpha = FastCipher::new(&key, Domain::Alphanumeric, SecurityLevel::Quantum128).unwrap();
    group.bench_function("alpha36-8-q128", |b| {
        b.iter(|| alpha.encrypt(black_box(b"tweak"), black_box("hello123")).unwrap());
    });

    // Classical security for comparison
    let classical = FastCipher::new(&key, Domain::Decimal, SecurityLevel::Classical128).unwrap();
    group.bench_function("decimal-10-c128", |b| {
        b.iter(|| classical.encrypt(black_box(b"tweak"), black_box("1234567890")).unwrap());
    });

    group.finish();
}

fn bench_fast_batch(c: &mut Criterion) {
    let key = FastKey::new(&[0x42u8; 16]).unwrap();
    let mapping = Domain::Decimal.mapping();

    // Pre-compute state (amortize setup cost)
    let state = FastCipherState::setup(&key, b"411111", 10, 6, SecurityLevel::Quantum128).unwrap();

    c.bench_function("fast-batch-encrypt-precomputed-6digit", |b| {
        b.iter(|| {
            FastCipher::encrypt_with_state(
                black_box(&state),
                black_box("123456"),
                mapping.as_ref(),
            )
            .unwrap()
        });
    });
}

fn bench_fast_setup(c: &mut Criterion) {
    let key = FastKey::new(&[0x42u8; 16]).unwrap();

    c.bench_function("fast-setup-decimal-10-q128", |b| {
        b.iter(|| {
            FastCipherState::setup(
                black_box(&key),
                black_box(b"tweak"),
                black_box(10),
                black_box(10),
                SecurityLevel::Quantum128,
            )
            .unwrap()
        });
    });
}

fn bench_ff1(c: &mut Criterion) {
    let cipher = Ff1Cipher::new(&[0x42u8; 16], 10).unwrap();

    let mut group = c.benchmark_group("ff1-encrypt");

    group.bench_function("decimal-9", |b| {
        b.iter(|| cipher.encrypt(black_box(b"tweak"), black_box("123456789")).unwrap());
    });

    group.bench_function("decimal-10", |b| {
        b.iter(|| cipher.encrypt(black_box(b"tweak"), black_box("1234567890")).unwrap());
    });

    group.bench_function("decimal-16", |b| {
        b.iter(|| cipher.encrypt(black_box(b"tweak"), black_box("1234567890123456")).unwrap());
    });

    group.finish();
}

fn bench_comparison(c: &mut Criterion) {
    let key_bytes = [0x42u8; 16];
    let fast_key = FastKey::new(&key_bytes).unwrap();
    let fast_cipher =
        FastCipher::new(&fast_key, Domain::Decimal, SecurityLevel::Quantum128).unwrap();
    let ff1_cipher = Ff1Cipher::new(&key_bytes, 10).unwrap();

    let mut group = c.benchmark_group("fast-vs-ff1");

    for len in [9, 10, 16] {
        let pt: String = (0..len).map(|i| char::from(b'0' + (i % 10) as u8)).collect();

        group.bench_with_input(BenchmarkId::new("FAST-q128", len), &pt, |b, pt| {
            b.iter(|| fast_cipher.encrypt(black_box(b"tweak"), black_box(pt)).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("FF1", len), &pt, |b, pt| {
            b.iter(|| ff1_cipher.encrypt(black_box(b"tweak"), black_box(pt)).unwrap());
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_fast_encrypt,
    bench_fast_batch,
    bench_fast_setup,
    bench_ff1,
    bench_comparison
);
criterion_main!(benches);
