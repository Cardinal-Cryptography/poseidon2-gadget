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
        4 => vec![
            from_hex("10dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e7"),
            from_hex("0c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740b"),
            from_hex("00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15"),
            from_hex("222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428b"),
        ],
        8 => vec![
            from_hex("05bffb5e301d8c468c35e24eb2165b6b71725fb7ac9a48efe5ce041bdb05676d"),
            from_hex("2aa7a81812688343fc6d78073312996d75f4c5505db0ed22af5ec0df7888cdc7"),
            from_hex("2f5856fd71dab60d78cc3af15a89c1e4d61ba189849a4cea10acc1dd228faf00"),
            from_hex("12299a260999ac95d271e184968cda40bd4358877a6dcf43d779251fffa61348"),
            from_hex("1443aad4693d692a62a8e21f03d5643a123f0c8783a3d27c275f9d01089685fb"),
            from_hex("21561b0204a44488082e31472f5885a3adc179bb278233aedc4b316369ec9937"),
            from_hex("0c7cc2afa53f9898f30a69b294a4e24f6b2176e1ae0ca49b021792d55e34e97d"),
            from_hex("2dd221096053de389fae88e7caa5c43ab55e22aeb758ee130d1246c1dff47b53"),
        ],
        12 => vec![
            from_hex("20bb1e98f40bfe80b8e2f2c885ea13a2ea1f146ff61218c31075ad79dd8f4ffa"),
            from_hex("1ed6abd05c8d678fa14c0c77d90f02fa1f8af249915fa6518f5f8d5e5c649fb2"),
            from_hex("29107b18658b47d566f5063975d6bbc504382b81777e0796c7cb81f9b4e2cf46"),
            from_hex("134ceec3ec069dd76fc9804ff029c2c27c5646986ff5dbeb17091d9c479ae923"),
            from_hex("0ee2e4f4a3c23a1b71834d1a95ea402504b8d68fab6f74855c884df898c286f9"),
            from_hex("0a469d3f3cb250181cc1e70c8227dace349b1c52fe8f7375744c8be5b80771e5"),
            from_hex("0cfa92ab38d116f1cdc24ecc083ad1cb17a215de9968726a81970dde9cca70d6"),
            from_hex("173df1a0df85f4533605f9578b1f58ccadf1f810e1fcca66808382efa84d684a"),
            from_hex("2ced3bf3cf641c12a311b16b4107663388876a894e70c28c5498946c7fd8dcd4"),
            from_hex("0912073a16428c84bfbb6170108adf6d168100ac5587c23c9405cf1f7ca8f13b"),
            from_hex("250b310cd13063ee49c78680c1434853968f464d2fc99166c23a2e330dd71d54"),
            from_hex("08b593b39852f7ad095a03a3eee546c388e02896d460454c6f1887c8d1c82e37"),
        ],
        16 => vec![
            from_hex("269aaf7c0e0ae1a709c1b7cd137c366a3ef21c0ca7d9fb2b33b5a1ae235768e4"),
            from_hex("30543ee04032614e317229edfaf3b27da10dd0792f35ecb2fb82a20c30eb1de3"),
            from_hex("017416b13160b7d8d73ffd44efc75ce642f1d002e332ad4bd68469b8b83c5fc4"),
            from_hex("09b103f438a43f1aabb6bc5d3490d3c443d773b966d902d36c81490614939eaf"),
            from_hex("08f9e81ea21aa882da55bde42c830d261462c4489451ab181513614983fcdb30"),
            from_hex("026d2cf77cf485777fb797f7c3bf17acafcb3679549ac98acb6e430eb53e4be5"),
            from_hex("0652442bfa09590b710b3273f0d3c3de61defe08359aa8289b63f36eec1d7a7b"),
            from_hex("0d6e46bf1e3725ff884f82602321db7d05c152349b4cd1117195e5f778f9c27b"),
            from_hex("285754e689291a5f02e4a3c9b07359d3fc33a687a755f842cc45a037774d0542"),
            from_hex("09a4884b8ce2a5dc8eee7e181526dd65567e70aa4cb62c3d128e7d94345a4dc4"),
            from_hex("06af44dac4ca6cc95e692a20907607defa711623ca94934bea9d70bd555a594d"),
            from_hex("0f8b7738afe6bd0d66cb58970bf7484be2c67a4519d1406f074ae165ab5d2ad5"),
            from_hex("294dbe90e673accdcc6d7211bb0ac3aab902a88476ef7f7ac6fe3ba7b128c71a"),
            from_hex("05c3f9cecad533b14bace3f9d7d7713ccf40c9429b4fce2cfa3aa4ee3d4ae039"),
            from_hex("26cbff872ac3df2a3787878f24ee28b6ad4f1dcab41126b80f4038f40510d7e1"),
            from_hex("1ba0b493c987b9c1424ede9239ba100dc005e717aa71ca6d6a605561e379bdce"),
        ],

        _ => panic!("Not implemented."),
    };

    let mut matrix_partial = [[F::ONE; T]; T];

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
