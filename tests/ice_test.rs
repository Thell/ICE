// Testing for base implmentation of ICE

#[test]
fn encrypt_level0() {
    let ice_level = 0;
    let ice_key = [0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00];

    let mut test_ice = ice::IceKey::new(ice_level);
    test_ice.key_set(&ice_key);

    let expect_text: String = "abcdefgh".to_string();
    let mut ciphertext = Vec::new();

    let mut ctext = [0; 8];
    let mut ptext = [0; 8];
    expect_text.as_bytes().chunks_exact(8).for_each(|chunk| {
        ptext.copy_from_slice(chunk);
        test_ice.encrypt(&ptext, &mut ctext);
        ciphertext.extend_from_slice(&ctext);
    });
    assert_eq!(ciphertext, [195, 233, 103, 103, 181, 234, 50, 163]);
}

#[test]
fn decrypt_level0() {
    let ice_level = 0;
    let ice_key = [0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00];

    let mut test_ice = ice::IceKey::new(ice_level);
    test_ice.key_set(&ice_key);

    let expect_text: String = "abcdefgh".to_string();
    let ciphertext = vec![195, 233, 103, 103, 181, 234, 50, 163];

    let mut ctext = [0; 8];
    let mut ptext = [0; 8];
    let mut plaintext = Vec::new();
    ciphertext.chunks_exact(8).for_each(|chunk| {
        ctext.copy_from_slice(chunk);
        test_ice.decrypt(&ctext, &mut ptext);
        plaintext.extend_from_slice(&ptext);
    });
    let plaintext = String::from_utf8(plaintext).unwrap();
    assert_eq!(plaintext, expect_text);
}

#[test]
fn encrypt_level1() {
    let ice_level = 1;
    let ice_key = [0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00];

    let mut test_ice = ice::IceKey::new(ice_level);
    test_ice.key_set(&ice_key);

    let expect_text: String = "abcdefgh".to_string();
    let mut ciphertext = Vec::new();

    let mut ctext = [0; 8];
    let mut ptext = [0; 8];
    expect_text.as_bytes().chunks_exact(8).for_each(|chunk| {
        ptext.copy_from_slice(chunk);
        test_ice.encrypt(&ptext, &mut ctext);
        ciphertext.extend_from_slice(&ctext);
    });
    assert_eq!(ciphertext, [49, 188, 85, 204, 107, 67, 206, 70]);
}

#[test]
fn decrypt_level1() {
    let ice_level = 1;
    let ice_key = [0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00];

    let mut test_ice = ice::IceKey::new(ice_level);
    test_ice.key_set(&ice_key);

    let expect_text: String = "abcdefgh".to_string();
    let ciphertext = vec![49, 188, 85, 204, 107, 67, 206, 70];

    let mut ctext = [0; 8];
    let mut ptext = [0; 8];
    let mut plaintext = Vec::new();
    ciphertext.chunks_exact(8).for_each(|chunk| {
        ctext.copy_from_slice(chunk);
        test_ice.decrypt(&ctext, &mut ptext);
        plaintext.extend_from_slice(&ptext);
    });
    let plaintext = String::from_utf8(plaintext).unwrap();
    assert_eq!(plaintext, expect_text);
}

#[test]
fn encrypt_level2() {
    let ice_level = 2;
    let ice_key = [0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00, 0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00];

    let mut test_ice = ice::IceKey::new(ice_level);
    test_ice.key_set(&ice_key);

    let expect_text: String = "abcdefgh".to_string();
    let mut ciphertext = Vec::new();

    let mut ctext = [0; 8];
    let mut ptext = [0; 8];
    expect_text.as_bytes().chunks_exact(8).for_each(|chunk| {
        ptext.copy_from_slice(chunk);
        test_ice.encrypt(&ptext, &mut ctext);
        ciphertext.extend_from_slice(&ctext);
    });
    assert_eq!(ciphertext, [234, 6, 99, 4, 147, 138, 221, 23]);
}

#[test]
fn decrypt_level2() {
    let ice_level = 2;
    let ice_key = [0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00, 0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00];

    let mut test_ice = ice::IceKey::new(ice_level);
    test_ice.key_set(&ice_key);

    let expect_text: String = "abcdefgh".to_string();
    let ciphertext = vec![234, 6, 99, 4, 147, 138, 221, 23];

    let mut ctext = [0; 8];
    let mut ptext = [0; 8];
    let mut plaintext = Vec::new();
    ciphertext.chunks_exact(8).for_each(|chunk| {
        ctext.copy_from_slice(chunk);
        test_ice.decrypt(&ctext, &mut ptext);
        plaintext.extend_from_slice(&ptext);
    });
    let plaintext = String::from_utf8(plaintext).unwrap();
    assert_eq!(plaintext, expect_text);
}