//! Generates matrix for the Poseidon 2 full round, with `1` *not* subtracted from the diagonal.

use ff::FromUniformBytes;

use super::Mds;

/// Generate matrix for the full round for the special case T=3.
fn generate_matrix_width_3<F: FromUniformBytes<64> + Ord, const T: usize>() -> Mds<F, T> {
    assert!(T == 3);

    let mut matrix_full = [[F::ONE; T]; T];

    #[allow(clippy::needless_range_loop)]
    for i in 0..T {
        matrix_full[i][i] = F::from_u128(2);
    }

    matrix_full
}

/// Generates matrix for the full round for the case T=4k.
fn generate_matrix_width_4k<F: FromUniformBytes<64> + Ord, const T: usize>() -> Mds<F, T> {
    assert!(T >= 4 && T % 4 == 0);

    let f = |x| F::from_u128(x);

    let matrix_4_4 = [
        [f(5), f(7), f(1), f(3)],
        [f(4), f(6), f(1), f(1)],
        [f(1), f(3), f(5), f(7)],
        [f(1), f(1), f(4), f(6)],
    ];

    let mut matrix_full = [[F::ZERO; T]; T];

    if T == 4 {
        for i in 0..T {
            for j in 0..T {
                matrix_full[i][j] = matrix_4_4[i][j];
            }
        }
    } else {
        for i in 0..T {
            for j in 0..T {
                if i / 4 == j / 4 {
                    matrix_full[i][j] = f(2) * matrix_4_4[i % 4][j % 4];
                } else {
                    matrix_full[i][j] = matrix_4_4[i % 4][j % 4];
                }
            }
        }
    }

    matrix_full
}

/// Generate matrix for the Poseidon 2 full round, with `1` *not* subtracted from the diagonal.
pub fn generate<F: FromUniformBytes<64> + Ord, const T: usize>() -> Mds<F, T> {
    if T == 3 {
        generate_matrix_width_3()
    } else {
        assert!(T >= 4 && T % 4 == 0);
        generate_matrix_width_4k()
    }
}
