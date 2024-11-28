//! Generates matrix for the Poseidon 2 partial round, with `1` subtracted from the diagonal.

use ff::FromUniformBytes;

use super::Mds;

/// Generate the matrix for the special case T=3, with `1` subtracted from the diagonal.
fn generate_matrix_m_1_width_3<F: FromUniformBytes<64> + Ord, const T: usize>() -> Mds<F, T> {
    assert!(T == 3);

    let mut matrix = [[F::ONE; T]; T];

    matrix[2][2] = F::from_u128(2);

    matrix
}

/// Generate the matrix for the case T=4k, with `1` subtracted from the diagonal.
/// Constants generated using
/// https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage
/// with `p` switched to BN254/BN256 and `t` set to an appropriate value.
fn generate_matrix_m_1_width_4k<F: FromUniformBytes<64> + Ord, const T: usize>() -> Mds<F, T> {
    assert!(T >= 4 && T % 4 == 0);

    let from_hex = |a: &str| -> F {
        let mut a = hex::decode(a).unwrap();
        a.reverse();
        a.extend([0; 32]);
        let a: [u8; 64] = a.try_into().unwrap();
        F::from_uniform_bytes(&a)
    };

    let diag = match T {
        8 => vec![
            from_hex("2107f5cf79a11c871aed7da43074f84648a941ba6612a793cd988da73afb1a71"),
            from_hex("29ab8490077f26752b1f4c367a98027e329127f4e14551f080a3e0fa1ec2ba54"),
            from_hex("067ec7e2a41250eaf5bea19a8840f650db3f551f9c51c828d465a1c85dd9d048"),
            from_hex("24df6b655b777cf543d766cf2c2d859b0cf6c6e13ddf34c9763968e5b48a7630"),
            from_hex("01e21a13937d6d0e1d523ad746679ab8821e8e3dc4c3e7e623bd8f683fd40975"),
            from_hex("1ade4882c00b5e5f5d81aff15978a3a39d5e18eda982781a9a520d0c8b2bc282"),
            from_hex("2015ab9b1ca880207659fca9facdb10fe4dcb28892e15fe363bff3c7f286bd5d"),
            from_hex("030f4266095db3b3f5dc9d93da3766fae31a6e540c5c85c8b5d18f1d86333d11"),
        ],
        _ => panic!("Not implemented."),
    };

    let mut matrix_partial = [[F::ONE; T]; T];

    #[allow(clippy::manual_memcpy)] // Suppress Clippy false positive.
    for i in 0..T {
        matrix_partial[i][i] = diag[i];
    }

    matrix_partial
}

/// Generate matrix for the Poseidon 2 partial round, with `1` subtracted from the diagonal.
pub fn generate_matrix_m_1<F: FromUniformBytes<64> + Ord, const T: usize>() -> Mds<F, T> {
    if T == 3 {
        generate_matrix_m_1_width_3()
    } else {
        assert!(T >= 4 && T % 4 == 0);
        generate_matrix_m_1_width_4k()
    }
}
