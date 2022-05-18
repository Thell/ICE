pub mod ice;
pub mod icefast;
pub mod lib;

fn main() {
    let ice_key = [0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00];
    let mut test_ice = ice::IceKey::new(0);
    test_ice.key_set(&ice_key);

    let isk = &test_ice.key.keysched[0];
    let mut zero_count = 0;
    for _ in 0..100_000_000 {
        let x = test_ice.ice_f(1, &isk);
        if x == 0 {
            zero_count += 1;
        }
    }
    println!("zero_count: {}", zero_count);

    let mut test_ice = icefast::IceKey::new(0);
    test_ice.key_set(&ice_key);

    let expect_text: String = "abcdefgh".to_string();
    let mut data = expect_text.as_bytes().to_owned();
    test_ice.encrypt(&mut data);
    assert_eq!(data, [195, 233, 103, 103, 181, 234, 50, 163]);

    // let mut test_ice = icefast::IceKey::new(0);
    // test_ice.key_set(&ice_key);

    // let isk = &test_ice.key.keysched[0];
    // let mut zero_count = 0;
    // for _ in 0..100_000_000 {
    //     // let x = test_ice.ice_f(1, &isk);
    //         // let lp = test_ice.ice_f_eands(1, &isk);
    //         let x = test_ice.ice_f(1, &isk);
    //     if x == 0 {
    //         zero_count += 1;
    //     }
    // }
    // println!("zero_count: {}", zero_count);

    // let expect_text: String = "abcdefgh".to_string().repeat(100_000_000);
    // // println!("expect: {}", expect_text);
    // let mut ciphertext = Vec::new();

    // let mut ctext = [0; 8];
    // let mut ptext = [0; 8];
    // expect_text.as_bytes().chunks_exact(8).for_each(|chunk| {
    //     ptext.copy_from_slice(chunk);
    //     test_ice.encrypt(&ptext, &mut ctext);
    //     ciphertext.extend_from_slice(&ctext);
    // });
    // // println!("ciphertext: {:?}", ciphertext);

    // let mut ctext = [0; 8];
    // let mut ptext = [0; 8];
    // let mut plaintext = Vec::new();
    // ciphertext.chunks_exact(8).for_each(|chunk| {
    //     ctext.copy_from_slice(chunk);
    //     test_ice.decrypt(&ctext, &mut ptext);
    //     plaintext.extend_from_slice(&ptext);
    // });
    // // println!("plaintext: {:?}", plaintext);
    // let plaintext = String::from_utf8(plaintext).unwrap();
    // // println!("plaintext: {:?}", plaintext);
    // assert_eq!(plaintext, expect_text);
}
