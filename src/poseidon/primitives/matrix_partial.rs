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
        3 => vec![
            from_hex("0000000000000000000000000000000000000000000000000000000000000001"),
            from_hex("0000000000000000000000000000000000000000000000000000000000000001"),
            from_hex("0000000000000000000000000000000000000000000000000000000000000002"),
        ],
        4 => vec![
            from_hex("2a65492fb4b550937ede04338113237e3070501d678e4c6140e74b893bd3e4c3"),
            from_hex("2229efa06652011c04095cbe090a8f1e8b3388ba29b72217781136ec486347b9"),
            from_hex("2f10c2ffb9f2fa48e024d818363ad7e879bcba19b9ffad3b435a5cf928cc3e80"),
            from_hex("0acf1bd376a789f63c6e54ddecfdf594b0042992f9e5bda460c1e6dea97b9ce0"),
        ],
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
        12 => vec![
            from_hex("125ba84289c4ac03032a20dcd753c2dc84db2f4ec73164e4a008a0374d96c575"),
            from_hex("1f4feb026c629e1da911bbea15b049d5397c8384dca108e354b208b24583615c"),
            from_hex("097c053794bb264265a5f2566073d1452aa6a2a39f7052f6d7d88ea42fda1a0f"),
            from_hex("118a0838eb3652e0847185e5b48bbcad00064aa83b0634b764ecf7e03e177d23"),
            from_hex("25da9858e6a1030da0fe6b7c68cdf1e0e0d604e8d2f3d00c192f80c1902f6287"),
            from_hex("270286407d5c3c535821aeb660fd7968d9acf6f2e96e16bd42c0ce72135b3666"),
            from_hex("19d2e54f06931b2a2b6babf7df7e4403aee040cfeb3f5f14f114fc07b82739bf"),
            from_hex("025367b0e54c8fa884c3038c9bac735be6f076e88d082d4e41ba872414e20250"),
            from_hex("26ee2826b1d45dee922c0c0c21c64a52fe31292cbddef68be072e26a61e16746"),
            from_hex("0d5d4d80b95b4c93221c79b3a4940bf6ecde13615f554f44e14f4837203eecdf"),
            from_hex("2e9da16c09ae4b4899b52ade435370eeb693509b4b1144843517602878583cad"),
            from_hex("27ee2bed1d049531d31a15bc511f54e0cbf1dfea2eea31d66c61491522d42d0d"),
        ],
        16 => vec![
            from_hex("1069f49d027e754ae31b305e4b56d72409af528d1230168d71141e4826138f76"),
            from_hex("1006120870517a8b814af8aa56ac663e78a186113100c8cb59311e1fd90f3bb5"),
            from_hex("2b029f0bde7122c5cb89a9a35172f15ecb150b538168438432b88b672d1f4e6d"),
            from_hex("0ce0f9848cdd40139e4df90e845d69ed6bd3abf7053a83c52f347d52a0a4a52a"),
            from_hex("2f449c6050e2127783bc351a09a63a4c39950e1f1b6cff1e280287df84cda4a0"),
            from_hex("0c738f699345862a9d7a22cfedd80f659892784131d31579dffbff8ef96dc80c"),
            from_hex("13fc80ddc48a45a04e006a22167a606d106312ec832547f007ee8c7fbf2a6ab2"),
            from_hex("24b25e69ccb7cbc22834d1b70587cef1c397399a58a7812573672aabf490fb8a"),
            from_hex("015dae680b806c42c0d97d9d4234b265cd6da3087370aec7d0f9055ee6dd01af"),
            from_hex("0c5973e2772b94b423469963e794999292c88bd2e9efe27331737eba121b89a0"),
            from_hex("09768950e56823cccb39aabe69c3f2ac78ac3a36d048d157fec02d6fb78fd7b9"),
            from_hex("08d993c569c16debdb53b62090180820caaebbeaef47aa6daaa85e5996361e45"),
            from_hex("05f453b0401327f51bbda113536d12acf0d0f376c561a37b176fc4358fe97b09"),
            from_hex("149b7e2690eddaabc0feac8b91acb78c3817bfe7d414ac671cc6057b227665db"),
            from_hex("1036438e7f01e45291cf7a2aa669c52c89fb8a797f87591f1f53452d66bbd7f7"),
            from_hex("0b560d5cde629f1e714add1c5f7a1e0f42f56c26b15a02129e0667ecf375bf75"),
        ],
        _ => panic!("Partial matrix present only for state sizes of 3, 4, 8, 12, 16."),
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
