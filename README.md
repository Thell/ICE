# SIMD Information Concealment Engine

This is my attempt at implmenting [ICE][darkside] with SIMD instructions.
I am specifically aiming at use in decrypting for a specific key using Thin-ICE
but I don't plan on optimizing the instance creation (sbox lookup table, and
simd Galois functions) or Thin-ICE itself until I figure out how to add get the
main `ice_f()` loop vectorized.

* _Level 0 (or Thin-ICE) uses 8 rounds, while higher levels n use 16n rounds._

## Start

I will be using Matthew's c code as a reference implementation and, hopefully, incrementally adding intrinsics. First, basic optimizations to the rust code
will be done to make things easier.

Testing is done using a the bytes from from the original c source code for `abcdefgh` at each level.

## Notes 1

After some initial cleanup and changes these are the improvements seen...

__Initial__: (Release build)

```python
running 8 tests
test decrypt_level0_10kbench ... bench:     429,745 ns/iter (+/- 14,646)
test decrypt_level0_bench    ... bench:         138 ns/iter (+/- 2)
test decrypt_level1_bench    ... bench:         189 ns/iter (+/- 3)
test decrypt_level2_bench    ... bench:         270 ns/iter (+/- 12)
test encrypt_level0_10kbench ... bench:     431,752 ns/iter (+/- 9,430)
test encrypt_level0_bench    ... bench:         127 ns/iter (+/- 23)
test encrypt_level1_bench    ... bench:         175 ns/iter (+/- 2)
test encrypt_level2_bench    ... bench:         260 ns/iter (+/- 1)
```

__Initial__: (Release build with Opt-Level 3, LTO, codegen-units 1, native cpu)

```python
running 8 tests
test decrypt_level0_10kbench ... bench:     399,127 ns/iter (+/- 83,596)
test decrypt_level0_bench    ... bench:         133 ns/iter (+/- 2)
test decrypt_level1_bench    ... bench:         190 ns/iter (+/- 60)
test decrypt_level2_bench    ... bench:         258 ns/iter (+/- 8)
test encrypt_level0_10kbench ... bench:     395,702 ns/iter (+/- 48,113)
test encrypt_level0_bench    ... bench:         123 ns/iter (+/- 2)
test encrypt_level1_bench    ... bench:         170 ns/iter (+/- 4)
test encrypt_level2_bench    ... bench:         248 ns/iter (+/- 3)
```

__Phase 1__: (Cleanup, flow, iterator usage, in-place encrypt/decrypt - Release w/o Opts)

```python
running 8 tests
test decrypt_fast_level0_10kbench ... bench:     393,635 ns/iter (+/- 9,490)
test decrypt_fast_level0_bench    ... bench:         125 ns/iter (+/- 2)
test decrypt_fast_level1_bench    ... bench:         159 ns/iter (+/- 2)
test decrypt_fast_level2_bench    ... bench:         232 ns/iter (+/- 5)
test encrypt_fast_level0_10kbench ... bench:     309,420 ns/iter (+/- 3,900)
test encrypt_fast_level0_bench    ... bench:         113 ns/iter (+/- 1)
test encrypt_fast_level1_bench    ... bench:         151 ns/iter (+/- 42)
test encrypt_fast_level2_bench    ... bench:         223 ns/iter (+/- 4)
```

__Phase 1__: (Release w/ options.)

```python
running 8 tests
test decrypt_fast_level0_10kbench ... bench:     312,087 ns/iter (+/- 6,475)
test decrypt_fast_level0_bench    ... bench:         117 ns/iter (+/- 3)
test decrypt_fast_level1_bench    ... bench:         154 ns/iter (+/- 2)
test decrypt_fast_level2_bench    ... bench:         230 ns/iter (+/- 5)
test encrypt_fast_level0_10kbench ... bench:     308,107 ns/iter (+/- 68,092)
test encrypt_fast_level0_bench    ... bench:         110 ns/iter (+/- 2)
test encrypt_fast_level1_bench    ... bench:         145 ns/iter (+/- 38)
test encrypt_fast_level2_bench    ... bench:         221 ns/iter (+/- 3)
```

Phase 1 Notes:

* The 10k runs are actually 20k bytes (the basic `abcdefgh` * 10k)
* Notice the decrypt 10k in __Phase 1__. I don't know what is going on there but if I replace the reversed chunk iterator with a regular loop then the timing is `316,777` and `322,384` with and without opts respectively. So my guess is that reversed `chunk_exact` iterators are __not__ treated the same as the forward iterators without compile opts. I took a quick look with Godbolt and it didn't help much in identifying the issue so it might be worth revisiting someday.

## Notes 2

I've identified where simd optimizations _could_ be made and a couple of places intrinsics _could_ be used but the algo needs a bit more fine tuning for the compiler to automagically take advantage of vectorization.

[darkside]: http://www.darkside.com.au/ice/description.html
