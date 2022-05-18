// Benching for base implmentation of ICE

#[macro_use]
extern crate bencher;
use bencher::Bencher;

static KEY8: [u8; 8] = [0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00];
static KEY16: [u8; 16] = [
    0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00, 0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00,
];

static EXPECT_TEXT_SMALL: &str = "abcdefgh";
static CIPHER_TEXT_SMALL_LEVEL0: [u8; 8] = [195, 233, 103, 103, 181, 234, 50, 163];
static CIPHER_TEXT_SMALL_LEVEL1: [u8; 8] = [49, 188, 85, 204, 107, 67, 206, 70];
static CIPHER_TEXT_SMALL_LEVEL2: [u8; 8] = [234, 6, 99, 4, 147, 138, 221, 23];

fn encrypt_level0_bench(bench: &mut Bencher) {
    let mut test_ice = ice::IceKey::new(0);
    test_ice.key_set(&KEY8);
    bench.iter(|| {
        let mut ctext = [0; 8];
        let mut ptext = [0; 8];
        let mut ciphertext = Vec::new();
        EXPECT_TEXT_SMALL
            .as_bytes()
            .chunks_exact(8)
            .for_each(|chunk| {
                ptext.copy_from_slice(chunk);
                test_ice.encrypt(&ptext, &mut ctext);
                ciphertext.extend_from_slice(&ctext);
            });
        assert_eq!(ciphertext, CIPHER_TEXT_SMALL_LEVEL0);
    });
}

fn decrypt_level0_bench(bench: &mut Bencher) {
    let mut test_ice = ice::IceKey::new(0);
    test_ice.key_set(&KEY8);
    bench.iter(|| {
        let mut ctext = [0; 8];
        let mut ptext = [0; 8];
        let mut plaintext = Vec::new();
        CIPHER_TEXT_SMALL_LEVEL0.chunks_exact(8).for_each(|chunk| {
            ctext.copy_from_slice(chunk);
            test_ice.decrypt(&ctext, &mut ptext);
            plaintext.extend_from_slice(&ptext);
        });
        let plaintext = String::from_utf8(plaintext).unwrap();
        assert_eq!(plaintext, EXPECT_TEXT_SMALL);
    });
}

fn encrypt_level1_bench(bench: &mut Bencher) {
    let mut test_ice = ice::IceKey::new(1);
    test_ice.key_set(&KEY8);

    bench.iter(|| {
        let mut ctext = [0; 8];
        let mut ptext = [0; 8];
        let mut ciphertext = Vec::new();
        EXPECT_TEXT_SMALL
            .as_bytes()
            .chunks_exact(8)
            .for_each(|chunk| {
                ptext.copy_from_slice(chunk);
                test_ice.encrypt(&ptext, &mut ctext);
                ciphertext.extend_from_slice(&ctext);
            });
        assert_eq!(ciphertext, CIPHER_TEXT_SMALL_LEVEL1);
    });
}

fn decrypt_level1_bench(bench: &mut Bencher) {
    let mut test_ice = ice::IceKey::new(1);
    test_ice.key_set(&KEY8);

    bench.iter(|| {
        let mut ctext = [0; 8];
        let mut ptext = [0; 8];
        let mut plaintext = Vec::new();
        CIPHER_TEXT_SMALL_LEVEL1.chunks_exact(8).for_each(|chunk| {
            ctext.copy_from_slice(chunk);
            test_ice.decrypt(&ctext, &mut ptext);
            plaintext.extend_from_slice(&ptext);
        });
        let plaintext = String::from_utf8(plaintext).unwrap();
        assert_eq!(plaintext, EXPECT_TEXT_SMALL);
    });
}

fn encrypt_level2_bench(bench: &mut Bencher) {
    let mut test_ice = ice::IceKey::new(2);
    test_ice.key_set(&KEY16);

    bench.iter(|| {
        let mut ctext = [0; 8];
        let mut ptext = [0; 8];
        let mut ciphertext = Vec::new();
        EXPECT_TEXT_SMALL
            .as_bytes()
            .chunks_exact(8)
            .for_each(|chunk| {
                ptext.copy_from_slice(chunk);
                test_ice.encrypt(&ptext, &mut ctext);
                ciphertext.extend_from_slice(&ctext);
            });
        assert_eq!(ciphertext, CIPHER_TEXT_SMALL_LEVEL2);
    });
}

fn decrypt_level2_bench(bench: &mut Bencher) {
    let mut test_ice = ice::IceKey::new(2);
    test_ice.key_set(&KEY16);

    bench.iter(|| {
        let mut ctext = [0; 8];
        let mut ptext = [0; 8];
        let mut plaintext = Vec::new();
        CIPHER_TEXT_SMALL_LEVEL2.chunks_exact(8).for_each(|chunk| {
            ctext.copy_from_slice(chunk);
            test_ice.decrypt(&ctext, &mut ptext);
            plaintext.extend_from_slice(&ptext);
        });
        let plaintext = String::from_utf8(plaintext).unwrap();
        assert_eq!(plaintext, EXPECT_TEXT_SMALL);
    });
}

fn encrypt_level0_10kbench(bench: &mut Bencher) {
    let mut test_ice = ice::IceKey::new(0);
    test_ice.key_set(&KEY8);
    let text10k = EXPECT_TEXT_SMALL.repeat(10000);
    bench.iter(|| {
        let mut ctext = [0; 8];
        let mut ptext = [0; 8];
        let mut ciphertext = Vec::new();
        text10k
            .as_bytes()
            .chunks_exact(8)
            .for_each(|chunk| {
                ptext.copy_from_slice(chunk);
                test_ice.encrypt(&ptext, &mut ctext);
                ciphertext.extend_from_slice(&ctext);
            });
        assert_eq!(ciphertext.len(), text10k.len());
    });
}

fn decrypt_level0_10kbench(bench: &mut Bencher) {
    let mut test_ice = ice::IceKey::new(0);
    test_ice.key_set(&KEY8);
    let text10k = EXPECT_TEXT_SMALL.repeat(10000);
    bench.iter(|| {
        let mut ctext = [0; 8];
        let mut ptext = [0; 8];
        let mut ciphertext = Vec::new();
        text10k
            .as_bytes()
            .chunks_exact(8)
            .for_each(|chunk| {
                ptext.copy_from_slice(chunk);
                test_ice.encrypt(&ptext, &mut ctext);
                ciphertext.extend_from_slice(&ctext);
            });
        assert_eq!(ciphertext.len(), text10k.len());
    });
}

benchmark_group!(
    benches,
    encrypt_level0_bench,
    decrypt_level0_bench,
    encrypt_level1_bench,
    decrypt_level1_bench,
    encrypt_level2_bench,
    decrypt_level2_bench,
    encrypt_level0_10kbench,
    decrypt_level0_10kbench,
);
benchmark_main!(benches);
