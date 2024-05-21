# `poseidon 2`

[Poseidon2 hash function](https://eprint.iacr.org/2023/323.pdf) gadget for Halo2.

A fork of the [Poseidon gadget implementation](https://github.com/privacy-scaling-explorations/poseidon-gadget/blob/main/src/poseidon.rs).

Notes:

 * Requires Rust 1.72.0+.
 * Halo2 is instantiated with KZG and bn256.
 * Unit tests were not adapted and are expected to fail.
 * The correcntess of hashes produced in-circuit is verified in `cargo bench`
   against an off-circuit Poseidon2 implementation.
 * Some of the matrices in source files are described using the term *MDS*,
   which may be misleading. In Poseidon, all used matrices have a property
   called MDS (maximum distance separable). This is no longer true
   in Poseidon 2, but we did not refactor all occurences of this term.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
