/* Structure of a single round subkey */
#[derive(Copy, Clone, Debug)]
pub struct IceSubkey {
    val: [u32; 3],
}

/* Internal structure of the ICE_KEY structure */
pub struct IceKeyStruct {
    size: usize,
    rounds: usize,
    pub keysched: Vec<IceSubkey>,
}

#[warn(dead_code)]
pub struct IceKey {
    // typedef struct ice_key_struct	ICE_KEY;
    pub key: IceKeyStruct,
    // /* The S-boxes */
    // static unsigned long	ice_sbox[4][1024];
    sbox: [[u32; 1024]; 4],
    // static int		ice_sboxes_initialised = 0;
    sboxes_initialised: bool,
}

/* Modulo values for the S-boxes */
const ICE_SMOD: [[i32; 4]; 4] = [
    [333, 313, 505, 369],
    [379, 375, 319, 391],
    [361, 445, 451, 397],
    [397, 425, 395, 505],
];

/* XOR values for the S-boxes */
const ICE_SXOR: [[i32; 4]; 4] = [
    [0x83, 0x85, 0x9b, 0xcd],
    [0xcc, 0xa7, 0xad, 0x41],
    [0x4b, 0x2e, 0xd4, 0x33],
    [0xea, 0xcb, 0x2e, 0x04],
];

/* Expanded permutation values for the P-box */
const ICE_PBOX: [u32; 32] = [
    0x00000001, 0x00000080, 0x00000400, 0x00002000, 0x00080000, 0x00200000, 0x01000000, 0x40000000,
    0x00000008, 0x00000020, 0x00000100, 0x00004000, 0x00010000, 0x00800000, 0x04000000, 0x20000000,
    0x00000004, 0x00000010, 0x00000200, 0x00008000, 0x00020000, 0x00400000, 0x08000000, 0x10000000,
    0x00000002, 0x00000040, 0x00000800, 0x00001000, 0x00040000, 0x00100000, 0x02000000, 0x80000000,
];

/* The key rotation schedule */
const KEYROT: [i32; 16] = [0, 1, 2, 3, 2, 1, 3, 0, 1, 3, 2, 0, 3, 1, 0, 2];

/*
 * Galois Field multiplication of a by b, modulo m.
 * Just like arithmetic multiplication, except that additions and
 * subtractions are replaced by XOR.
 */
fn gf_mult(mut a: u32, mut b: u32, m: u32) -> u32 {
    let mut res: u32 = 0;
    while b != 0 {
        if b & 1 != 0 {
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

/*
 * Galois Field exponentiation.
 * Raise the base to the power of 7, modulo m.
 */
fn gf_exp7(b: u32, m: u32) -> u32 {
    if b == 0 {
        return 0;
    }
    let mut x = gf_mult(b, b, m);
    x = gf_mult(b, x, m);
    x = gf_mult(x, x, m);
    gf_mult(b, x, m)
}

/*
 * Carry out the ICE 32-bit P-box permutation.
 */
fn ice_perm32(mut x: u32) -> u32 {
    let mut res: u32 = 0;
    let pbox = &ICE_PBOX;
    for pb in pbox.iter().take(32) {
        if x & 1 != 0 {
            res |= pb;
        }
        x >>= 1;
    }
    res
}

#[warn(dead_code)]
impl IceKey {
    /*
     * Initialise the ICE S-boxes.
     * This only has to be done once.
     */
    fn sboxes_init(&mut self) {
        for i in 0..1024 {
            let col = (i >> 1) & 0xff;
            let row = (i & 0x1) | ((i & 0x200) >> 8);
            let mut x = gf_exp7(
                (col ^ ICE_SXOR[0][row] as usize).try_into().unwrap(),
                ICE_SMOD[0][row].try_into().unwrap(),
            ) << 24;
            self.sbox[0][i] = ice_perm32(x);

            x = gf_exp7(
                (col ^ ICE_SXOR[1][row] as usize).try_into().unwrap(),
                ICE_SMOD[1][row].try_into().unwrap(),
            ) << 16;
            self.sbox[1][i] = ice_perm32(x);

            x = gf_exp7(
                (col ^ ICE_SXOR[2][row] as usize).try_into().unwrap(),
                ICE_SMOD[2][row].try_into().unwrap(),
            ) << 8;
            self.sbox[2][i] = ice_perm32(x);

            x = gf_exp7(
                (col ^ ICE_SXOR[3][row] as usize).try_into().unwrap(),
                ICE_SMOD[3][row].try_into().unwrap(),
            );
            self.sbox[3][i] = ice_perm32(x);
        }
    }

    /*
     * Create a new ICE key.
     */
    pub fn new(level: usize) -> Self {
        let mut ik = IceKey {
            key: IceKeyStruct {
                size: 0,
                rounds: 0,
                keysched: Vec::new(),
            },
            sbox: [[0; 1024]; 4],
            sboxes_initialised: false,
        };

        if !ik.sboxes_initialised {
            ik.sboxes_init();
            ik.sboxes_initialised = true;
        }

        if level < 1 {
            // Thin-ICE
            ik.key.size = 1;
            ik.key.rounds = 8;
        } else {
            ik.key.size = level;
            ik.key.rounds = level * 16;
        }

        ik.key.keysched = vec![IceSubkey { val: [0; 3] }; ik.key.rounds];
        ik
    }

    /*
     * The single round ICE f function.
     */
    pub fn ice_f_ess(&self, p: u32, sk: &IceSubkey) -> (u32,u32) {
        /* Expanded 40-bit values */
        /* 20-bits on the Left half expansion */
        let tl = p >> 16 & 0x3ff | p.rotate_left(18) & 0xffc00;
        /* 20-bits on the Right half expansion */
        let tr = (p & 0x3ff) | ((p << 2) & 0xffc00);

        /* Salted expanded 40-bit values */
        /* Perform the salt permutation */
        let mut al = sk.val[2] & (tl ^ tr);
        let mut ar = al ^ tr;
        al ^= tl;

        /* XOR with the subkey */
        al ^= sk.val[0];
        ar ^= sk.val[1];
        (al, ar)
    }

    pub fn ice_f(&self, p: u32, sk: &IceSubkey) -> u32 {
        /* Expand, salt and split to 40-bit values */
        let (al, ar) = self.ice_f_ess(p, sk);

        /* S-box lookup and permutation */
        // 20-bits on the expansions >> 10 is guaranteed to be in the range
        // 0..1023 but these are 32-bit values so the compiler can't tell
        // when all we do is shift and will do a bounds check.
        // Masking the high bits is a workaround.
        // It'd be nice to use intrinsics here but they're not as performant.
        // self.sbox[0][al.bextr(10, 10) as usize]
        //     | self.sbox[1][al as usize & 0x3ff]
        //     | self.sbox[2][ar.bextr(10, 10) as usize]
        //     | self.sbox[3][ar as usize & 0x3ff]
        self.sbox[0][(al as usize >> 10) & 0x3ff]
            | self.sbox[1][al as usize & 0x3ff]
            | self.sbox[2][(ar as usize >> 10) & 0x3ff]
            | self.sbox[3][ar as usize & 0x3ff]
    }

    /// Encrypt data in-place.
    /// Data must be a multiple of 8 bytes.
    pub fn encrypt(&self, data: &mut [u8]) {
        assert!(data.len() % 8 == 0, "Data must be a multiple of 8 bytes");

        data.chunks_exact_mut(8).for_each(|chunk| {
            let mut l: u32 = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
            let mut r: u32 = u32::from_be_bytes(chunk[4..8].try_into().unwrap());
    
            self.key.keysched.chunks_exact(2).for_each(|pair| {
                l ^= self.ice_f(r, &pair[0]);
                r ^= self.ice_f(l, &pair[1]);
            });
    
            chunk[0..4].copy_from_slice(&r.to_be_bytes()[..]);
            chunk[4..8].copy_from_slice(&l.to_be_bytes()[..]);
        })
    }

    /*
     * Decrypt a block of 8 bytes of data with the given ICE key.
     */
    pub fn decrypt(&self, data: &mut [u8]) {
        assert!(data.len() % 8 == 0, "Data must be a multiple of 8 bytes");

        data.chunks_exact_mut(8).for_each(|chunk| {
            let mut l: u32 = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
            let mut r: u32 = u32::from_be_bytes(chunk[4..8].try_into().unwrap());
    
            self.key.keysched.chunks_exact(2).rev().for_each(|pair| {
                l ^= self.ice_f(r, &pair[1]);
                r ^= self.ice_f(l, &pair[0]);
            });
            // let mut i = (self.key.rounds as isize) - 1;
            // loop {
            //     if i <= 0 {
            //         break;
            //     }
            //     l ^= self.ice_f(r, &self.key.keysched[i as usize]);
            //     r ^= self.ice_f(l, &self.key.keysched[i as usize - 1]);

            //     i -= 2;
            // }

            chunk[0..4].copy_from_slice(&r.to_be_bytes()[..]);
            chunk[4..8].copy_from_slice(&l.to_be_bytes()[..]);
        })

        // let mut l: u32 = u32::from_be_bytes(ctext[0..4].try_into().unwrap());
        // let mut r: u32 = u32::from_be_bytes(ctext[4..8].try_into().unwrap());

        // for i in (0..self.key.rounds).rev().step_by(2) {
        //     l ^= self.ice_f(r, &self.key.keysched[i as usize]);
        //     r ^= self.ice_f(l, &self.key.keysched[i as usize - 1]);
        // }

        // ptext[0..4].copy_from_slice(&r.to_be_bytes()[..]);
        // ptext[4..8].copy_from_slice(&l.to_be_bytes()[..]);
    }

    /*
     * Set 8 rounds [n, n+7] of the key schedule of an ICE key.
     */
    fn key_sched_build(&mut self, kb: &mut [u16; 4], n: i32, keyrot: &[i32]) {
        for (i, kr) in keyrot.iter().enumerate().take(8) {
            let isk: &mut IceSubkey = &mut self.key.keysched[n as usize + i as usize];

            for j in 0..3 {
                (*isk).val[j] = 0;
            }

            for j in 0..15 {
                let curr_sk: &mut u32 = &mut (*isk).val[j % 3];

                for k in 0..4 {
                    let curr_kb = &mut kb[(kr + k) as usize & 3];
                    let bit = *curr_kb & 1;

                    *curr_sk = (*curr_sk << 1) | bit as u32;
                    *curr_kb = (*curr_kb >> 1) | ((bit ^ 1) << 15);
                }
            }
        }
    }

    /*
     * Set the key schedule of an ICE key.
     */
    pub fn key_set(&mut self, key: &[u8]) {
        if self.key.rounds == 8 {
            let mut kb: [u16; 4] = [0; 4];

            for i in 0..4 {
                kb[3 - i] = (key[i * 2] as u16) << 8 | key[i * 2 + 1] as u16;
            }

            self.key_sched_build(&mut kb, 0, &KEYROT);
            return;
        }

        for i in 0..self.key.size {
            let mut kb: [u16; 4] = [0; 4];

            for j in 0..4 {
                kb[3 - j] =
                    (key[i * 8 + j * 2] as u16) << 8 | key[i as usize * 8 + j * 2 + 1] as u16;
            }

            self.key_sched_build(&mut kb, (i * 8).try_into().unwrap(), &KEYROT);
            self.key_sched_build(
                &mut kb,
                (self.key.rounds - 8 - i * 8).try_into().unwrap(),
                &KEYROT[8..16],
            );
        }
    }

    /*
     * Return the key size, in bytes.
     */
    pub fn key_size(&self) -> i32 {
        (self.key.size * 8).try_into().unwrap()
    }

}
