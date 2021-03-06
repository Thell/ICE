use std::convert::TryInto;

const ICE_SMOD: [[i32; 4]; 4] = [
    [333, 313, 505, 369],
    [379, 375, 319, 391],
    [361, 445, 451, 397],
    [397, 425, 395, 505],
];

const ICE_SXOR: [[i32; 4]; 4] = [
    [0x83, 0x85, 0x9b, 0xcd],
    [0xcc, 0xa7, 0xad, 0x41],
    [0x4b, 0x2e, 0xd4, 0x33],
    [0xea, 0xcb, 0x2e, 0x04],
];

const ICE_PBOX: [u32; 32] = [
    0x00000001, 0x00000080, 0x00000400, 0x00002000, 0x00080000, 0x00200000, 0x01000000, 0x40000000,
    0x00000008, 0x00000020, 0x00000100, 0x00004000, 0x00010000, 0x00800000, 0x04000000, 0x20000000,
    0x00000004, 0x00000010, 0x00000200, 0x00008000, 0x00020000, 0x00400000, 0x08000000, 0x10000000,
    0x00000002, 0x00000040, 0x00000800, 0x00001000, 0x00040000, 0x00100000, 0x02000000, 0x80000000,
];

const ICE_KEYROT: [[i32; 8]; 2] = [[0, 1, 2, 3, 2, 1, 3, 0], [1, 3, 2, 0, 3, 1, 0, 2]];

fn gf_mult(a: i32, b: i32, m: i32) -> i32 {
    let mut res = 0;

    let mut a = a;
    let mut b = b;

    while b != 0 {
        if (b & 1) != 0 {
            res ^= a;
        }

        a <<= 1;
        b >>= 1;

        if a >= 256 {
            a ^= m;
        }
    }

    res
}

fn gf_exp7(b: i32, m: i32) -> u32 {
    if b == 0 {
        return 0;
    }

    let mut x = gf_mult(b, b, m);
    x = gf_mult(b, x, m);
    x = gf_mult(x, x, m);

    gf_mult(b, x, m) as u32
}

fn ice_perm32(x: u32) -> u32 {
    let mut res = 0;
    let mut idx = 0;

    let mut x = x;

    while x != 0 {
        if (x & 1) != 0 {
            res |= ICE_PBOX[idx];
        }

        idx += 1;
        x >>= 1;
    }

    res
}

#[derive(Debug)]
struct IceSubkey {
    val: [u32; 3],
}

impl IceSubkey {
    fn int_new() -> Self {
        IceSubkey { val: [0; 3] }
    }

    fn new(rounds: isize) -> Vec<Self> {
        let mut res = Vec::with_capacity(rounds as usize);

        for i in 0..rounds {
            res.push(IceSubkey::int_new());
        }

        res
    }
}

pub struct Ice {
    _size: isize,
    _rounds: isize,
    _keysched: Vec<IceSubkey>,

    ice_sbox: [[u32; 1024]; 4],
}

impl Ice {
    fn ice_sboxes_init(&mut self) {
        for i in 0..1024 {
            let col = (i >> 1) & 0xff;
            let row = (i & 1) | ((i & 0x200) >> 8);

            let x = gf_exp7(col as i32 ^ ICE_SXOR[0][row], ICE_SMOD[0][row]) << 24;
            self.ice_sbox[0][i] = ice_perm32(x);

            let x = gf_exp7(col as i32 ^ ICE_SXOR[1][row], ICE_SMOD[1][row]) << 16;
            self.ice_sbox[1][i] = ice_perm32(x);

            let x = gf_exp7(col as i32 ^ ICE_SXOR[2][row], ICE_SMOD[2][row]) << 8;
            self.ice_sbox[2][i] = ice_perm32(x);

            let x = gf_exp7(col as i32 ^ ICE_SXOR[3][row], ICE_SMOD[3][row]);
            self.ice_sbox[3][i] = ice_perm32(x);
        }
    }

    fn ice_f(&self, p: u32, sk: &IceSubkey) -> u32 {
        let tl = ((p >> 16) & 0x3ff) | (((p >> 14) | (p << 18)) & 0xffc00);
        let tr = (p & 0x3ff) | ((p << 2) & 0xffc00);

        let mut al = sk.val[2] & (tl ^ tr);
        let mut ar = al ^ tr;

        al ^= tl;
        al ^= sk.val[0];
        ar ^= sk.val[1];

        self.ice_sbox[0][(al >> 10) as usize]
            | self.ice_sbox[1][(al & 0x3ff) as usize]
            | self.ice_sbox[2][(ar >> 10) as usize]
            | self.ice_sbox[3][(ar & 0x3ff) as usize]
    }

    fn encrypt_int(&self, ptext: &[u8; 8]) -> [u8; 8] {
        let mut res = [0u8; 8];

        let mut l = ((ptext[0] as u32) << 24)
            | ((ptext[1] as u32) << 16)
            | ((ptext[2] as u32) << 8)
            | (ptext[3] as u32);
        let mut r = ((ptext[4] as u32) << 24)
            | ((ptext[5] as u32) << 16)
            | ((ptext[6] as u32) << 8)
            | (ptext[7] as u32);

        for i in (0..self._rounds).step_by(2) {
            l ^= self.ice_f(r, &self._keysched[i as usize]);
            r ^= self.ice_f(l, &self._keysched[i as usize + 1]);
        }

        for i in 0..4 {
            res[3 - i] = (r & 0xff).try_into().unwrap();
            res[7 - i] = (l & 0xff).try_into().unwrap();

            r >>= 8;
            l >>= 8;
        }

        res
    }

    fn decrypt_int(&self, ctext: &[u8; 8]) -> [u8; 8] {
        let mut res = [0u8; 8];

        let mut l = ((ctext[0] as u32) << 24)
            | ((ctext[1] as u32) << 16)
            | ((ctext[2] as u32) << 8)
            | (ctext[3] as u32);
        let mut r = ((ctext[4] as u32) << 24)
            | ((ctext[5] as u32) << 16)
            | ((ctext[6] as u32) << 8)
            | (ctext[7] as u32);

        for i in (1..self._rounds).step_by(2).rev() {
            l ^= self.ice_f(r, &self._keysched[i as usize]);
            r ^= self.ice_f(l, &self._keysched[i as usize - 1]);
        }

        for i in 0..4 {
            res[3 - i] = (r & 0xff).try_into().unwrap();
            res[7 - i] = (l & 0xff).try_into().unwrap();

            r >>= 8;
            l >>= 8;
        }

        res
    }

    fn schedule_build(&mut self, kb: &mut [u16; 4], n: isize, keyrot: &[i32; 8]) {
        for i in 0..8 {
            let kr = keyrot[i];
            let isk = &mut self._keysched[(n as usize + i)];

            for j in 0..3 {
                isk.val[j] = 0;
            }

            for j in 0..15 {
                let curr_sk = &mut isk.val[j % 3];

                for k in 0..4 {
                    let curr_kb = &mut kb[((kr + k) & 3) as usize];
                    let bit = *curr_kb & 1;

                    *curr_sk = (*curr_sk << 1) | bit as u32;
                    *curr_kb = (*curr_kb >> 1) | ((bit ^ 1) << 15);
                }
            }
        }
    }

    fn set(&mut self, key: &[u8]) {
        if self._rounds == 8 {
            let mut kb = [0u16; 4];

            for i in 0..4 {
                kb[3 - i] = ((key[i * 2] as u16) << 8) | key[i * 2 + 1] as u16;
            }

            self.schedule_build(&mut kb, 0, &ICE_KEYROT[0]);
            return;
        }

        for i in 0..self._size {
            let mut kb = [0u16; 4];

            for j in 0..4 {
                kb[3 - j] = ((key[i as usize * 8 + j * 2] as u16) << 8)
                    | (key[i as usize * 8 + j * 2 + 1] as u16);
            }

            self.schedule_build(&mut kb, (i * 8).try_into().unwrap(), &ICE_KEYROT[0]);
            self.schedule_build(&mut kb, self._rounds - 8 - i * 8, &ICE_KEYROT[1]);
        }
    }

    pub fn block_size(&self) -> usize {
        8
    }

    pub fn key_size(&self) -> isize {
        self._size * 8
    }

    pub fn new(csgo_version: u32) -> Self {
        // This is the version of the client, this basically increments with each update.
        // This needs to be updated everytime the client receives a steam update.
        let csgo_str = [b'C', b'S', b'G', b'O'];

        let version_4_8 = [
            ((csgo_version) & 0xff) as u8,
            ((csgo_version >> 8) & 0xff) as u8,
            ((csgo_version >> 16) & 0xff) as u8,
            ((csgo_version >> 24) & 0xff) as u8,
        ];

        let version_8_12 = [
            ((csgo_version >> 2) & 0xff) as u8,
            ((csgo_version >> 10) & 0xff) as u8,
            ((csgo_version >> 18) & 0xff) as u8,
            ((csgo_version >> 26) & 0xff) as u8,
        ];

        let version_12_16 = [
            ((csgo_version >> 4) & 0xff) as u8,
            ((csgo_version >> 12) & 0xff) as u8,
            ((csgo_version >> 20) & 0xff) as u8,
            ((csgo_version >> 28) & 0xff) as u8,
        ];

        let csgo_ice_key = [csgo_str, version_4_8, version_8_12, version_12_16].concat();

        Self::new_int(2, &csgo_ice_key)
    }

    fn new_int(size: isize, key: &[u8]) -> Self {
        assert!(key.len() == 16);
        let mut res = Ice {
            _size: size,
            _rounds: size * 16,
            ice_sbox: [[0; 1024]; 4],
            _keysched: IceSubkey::new(size * 16),
        };

        res.ice_sboxes_init();
        res.set(key);

        res
    }

    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() % self.block_size() != 0 || data.len() < self.block_size() {
            println!(
                "Data is not correctly aligned or smaller than the block size, decryption failed."
            );
            return None;
        }

        let mut ret = Vec::default();

        for i in (0..data.len()).step_by(8) {
            let mut arr = [0u8; 8];
            // im tired...
            arr[..8].clone_from_slice(&data[i..(8 + i)]);

            let dec = self.decrypt_int(&arr);

            for &k in dec.iter() {
                ret.push(k);
            }
        }

        Some(ret)
    }

    pub fn encrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() % self.block_size() != 0 || data.len() < self.block_size() {
            return None;
        }

        let mut ret = Vec::default();

        for i in (0..data.len()).step_by(8) {
            let mut arr = [0u8; 8];
            arr[..8].clone_from_slice(&data[i..(8 + i)]);

            let dec = self.encrypt_int(&arr);

            for &k in dec.iter() {
                ret.push(k);
            }
        }

        Some(ret)
    }
}