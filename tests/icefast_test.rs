// Testing for fast implmentation of ICE

#[path = "../src/icefast.rs"]
mod icefast;

static KEY8: [u8; 8] = [0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00];
static KEY16: [u8; 16] = [
    0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00, 0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00,
];

static EXPECT_TEXT_SMALL: &str = "abcdefgh";
static CIPHER_TEXT_SMALL_LEVEL0: [u8; 8] = [195, 233, 103, 103, 181, 234, 50, 163];
static CIPHER_TEXT_SMALL_LEVEL1: [u8; 8] = [49, 188, 85, 204, 107, 67, 206, 70];
static CIPHER_TEXT_SMALL_LEVEL2: [u8; 8] = [234, 6, 99, 4, 147, 138, 221, 23];

#[test]
fn encrypt_fast_level0() {
    let mut test_ice = icefast::IceKey::new(0);
    test_ice.key_set(&KEY8);

    let mut data = EXPECT_TEXT_SMALL.as_bytes().to_owned();
    test_ice.encrypt(&mut data);
    assert_eq!(data, CIPHER_TEXT_SMALL_LEVEL0);

}

#[test]
fn decrypt_fast_level0() {
    let mut test_ice = icefast::IceKey::new(0);
    test_ice.key_set(&KEY8);

    let mut data = CIPHER_TEXT_SMALL_LEVEL0.to_owned();
    test_ice.decrypt(&mut data);
    let plaintext = String::from_utf8(data.to_vec()).unwrap();
    assert_eq!(plaintext, EXPECT_TEXT_SMALL);
}

#[test]
fn encrypt_fast_level1() {
    let mut test_ice = icefast::IceKey::new(1);
    test_ice.key_set(&KEY8);

    let mut data = EXPECT_TEXT_SMALL.as_bytes().to_owned();
    test_ice.encrypt(&mut data);
    assert_eq!(data, CIPHER_TEXT_SMALL_LEVEL1);

}

#[test]
fn decrypt_fast_level1() {
    let mut test_ice = icefast::IceKey::new(1);
    test_ice.key_set(&KEY8);

    let mut data = CIPHER_TEXT_SMALL_LEVEL1.to_owned();
    test_ice.decrypt(&mut data);
    assert_eq!(data, EXPECT_TEXT_SMALL.as_bytes());
    let plaintext = String::from_utf8(data.to_vec()).unwrap();
    assert_eq!(plaintext, EXPECT_TEXT_SMALL);
}

#[test]
fn encrypt_fast_level2() {
    let mut test_ice = icefast::IceKey::new(2);
    test_ice.key_set(&KEY16);

    let mut data = EXPECT_TEXT_SMALL.as_bytes().to_owned();
    test_ice.encrypt(&mut data);
    assert_eq!(data, CIPHER_TEXT_SMALL_LEVEL2);

}

#[test]
fn decrypt_fast_level2() {
    let mut test_ice = icefast::IceKey::new(2);
    test_ice.key_set(&KEY16);

    let mut data = CIPHER_TEXT_SMALL_LEVEL2.to_owned();
    test_ice.decrypt(&mut data);
    let plaintext = String::from_utf8(data.to_vec()).unwrap();
    assert_eq!(plaintext, EXPECT_TEXT_SMALL);
}
