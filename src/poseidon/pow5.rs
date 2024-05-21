use core::panic;
use std::convert::TryInto;

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Cell, Chip, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Selector},
    poly::Rotation,
};

use super::{
    primitives::{Absorbing, Domain, Mds, Spec, Squeezing, State},
    PaddedWord, PoseidonInstructions, PoseidonSpongeInstructions,
};
use crate::utilities::Var;

/// Configuration for a [`Pow5Chip`].
#[derive(Clone, Debug)]
pub struct Pow5Config<F: Field, const WIDTH: usize, const RATE: usize> {
    pub(crate) state: [Column<Advice>; WIDTH],
    rc: [Column<Fixed>; WIDTH],
    sum: Column<Advice>,
    s_pre: Selector,
    s_full: Selector,
    s_partial: Selector,
    s_pad_and_add: Selector,

    pre_rounds: usize,
    half_full_rounds: usize,
    partial_rounds: usize,
    alpha: [u64; 4],
    round_constants: Vec<[F; WIDTH]>,
    #[allow(dead_code)]
    m_full: Mds<F, WIDTH>,
    diag: Vec<F>,
}

/// A Poseidon chip using an $x^5$ S-Box.
///
/// The chip is implemented using a single round per row for full rounds, and two rounds
/// per row for partial rounds.
#[derive(Debug)]
pub struct Pow5Chip<F: Field, const WIDTH: usize, const RATE: usize> {
    config: Pow5Config<F, WIDTH, RATE>,
}

impl<F: Field, const WIDTH: usize, const RATE: usize> Pow5Chip<F, WIDTH, RATE> {
    /// Configures this chip for use in a circuit.
    ///
    /// # Side-effects
    ///
    /// All columns in `state` will be equality-enabled.
    //
    // TODO: Does the rate need to be hard-coded here, or only the width? It probably
    // needs to be known wherever we implement the hashing gadget, but it isn't strictly
    // necessary for the permutation.
    pub fn configure<S: Spec<F, WIDTH, RATE>>(
        meta: &mut ConstraintSystem<F>,
        state: [Column<Advice>; WIDTH],
        rc: [Column<Fixed>; WIDTH],
        sum: Column<Advice>,
    ) -> Pow5Config<F, WIDTH, RATE> {
        assert_eq!(RATE, WIDTH - 1);
        // Generate constants for the Poseidon permutation.
        // This gadget requires R_F and R_P to be even.
        assert!(S::full_rounds() & 1 == 0);
        assert!(S::partial_rounds() & 1 == 0);
        let pre_rounds = 1;
        let half_full_rounds = S::full_rounds() / 2;
        let partial_rounds = S::partial_rounds();
        let (round_constants, m_full, mds_partial) = S::constants();

        let diag: Vec<F> = (0..WIDTH).map(|i| mds_partial[i][i]).collect();

        // This allows state words to be initialized (by constraining them equal to fixed
        // values), and used in a permutation from an arbitrary region. rc_a is used in
        // every permutation round, while rc_b is empty in the initial and final full
        // rounds, so we use rc_b as "scratch space" for fixed values (enabling potential
        // layouter optimisations).
        for column in state {
            meta.enable_equality(column);
        }
        meta.enable_equality(sum);

        rc.iter().for_each(|column| meta.enable_constant(*column));

        let s_pre = meta.selector();
        let s_full = meta.selector();
        let s_partial = meta.selector();
        let s_pad_and_add = meta.selector();

        let alpha = [5, 0, 0, 0];
        let pow_5 = |v: Expression<F>| {
            let v2 = v.clone() * v.clone();
            v2.clone() * v2 * v
        };

        meta.create_gate("pre round", |meta| {
            let s_pre = meta.query_selector(s_pre);
            Constraints::with_selector(
                s_pre,
                (0..WIDTH)
                    .map(|next_idx| {
                        let state_next = meta.query_advice(state[next_idx], Rotation::next());
                        let expr = (0..WIDTH)
                            .map(|idx| {
                                let state_cur = meta.query_advice(state[idx], Rotation::cur());
                                state_cur * m_full[next_idx][idx]
                            })
                            .reduce(|acc, term| acc + term)
                            .expect("WIDTH > 0");
                        expr - state_next
                    })
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("full round", |meta| {
            let s_full = meta.query_selector(s_full);

            Constraints::with_selector(
                s_full,
                (0..WIDTH)
                    .map(|next_idx| {
                        let state_next = meta.query_advice(state[next_idx], Rotation::next());
                        let expr = (0..WIDTH)
                            .map(|idx| {
                                let state_cur = meta.query_advice(state[idx], Rotation::cur());
                                let rc = meta.query_fixed(rc[idx], Rotation::cur());
                                pow_5(state_cur + rc) * m_full[next_idx][idx]
                            })
                            .reduce(|acc, term| acc + term)
                            .expect("WIDTH > 0");
                        expr - state_next
                    })
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("partial rounds", |meta| {
            let s_partial = meta.query_selector(s_partial);

            let rc_0 = meta.query_fixed(rc[0], Rotation::cur());
            let state_cur_0 = meta.query_advice(state[0], Rotation::cur());
            let state_next_0 = meta.query_advice(state[0], Rotation::next());
            let pow5_0 = pow_5(state_cur_0 + rc_0);

            let sum_expr = pow5_0.clone()
                + (1..WIDTH)
                    .map(|idx| meta.query_advice(state[idx], Rotation::cur()))
                    .reduce(|acc, term| acc + term)
                    .expect("WIDTH > 1");

            let sum_cell = meta.query_advice(sum, Rotation::cur());

            Constraints::with_selector(
                s_partial,
                (1..WIDTH)
                    .map(|idx| {
                        let state_next = meta.query_advice(state[idx], Rotation::next());
                        let state_cur = meta.query_advice(state[idx], Rotation::cur());

                        state_cur * diag[idx] + sum_cell.clone() - state_next
                    })
                    .chain(Some(pow5_0 * diag[0] + sum_cell.clone() - state_next_0))
                    .chain(Some(sum_expr - sum_cell.clone()))
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("pad-and-add", |meta| {
            let initial_state_rate = meta.query_advice(state[RATE], Rotation::prev());
            let output_state_rate = meta.query_advice(state[RATE], Rotation::next());

            let s_pad_and_add = meta.query_selector(s_pad_and_add);

            let pad_and_add = |idx: usize| {
                let initial_state = meta.query_advice(state[idx], Rotation::prev());
                let input = meta.query_advice(state[idx], Rotation::cur());
                let output_state = meta.query_advice(state[idx], Rotation::next());

                // We pad the input by storing the required padding in fixed columns and
                // then constraining the corresponding input columns to be equal to it.
                initial_state + input - output_state
            };

            Constraints::with_selector(
                s_pad_and_add,
                (0..RATE)
                    .map(pad_and_add)
                    // The capacity element is never altered by the input.
                    .chain(Some(initial_state_rate - output_state_rate))
                    .collect::<Vec<_>>(),
            )
        });

        Pow5Config {
            state,
            rc,
            sum,
            s_pre,
            s_full,
            s_partial,
            s_pad_and_add,
            pre_rounds,
            half_full_rounds,
            partial_rounds,
            alpha,
            round_constants,
            m_full,
            diag,
        }
    }

    /// Construct a [`Pow5Chip`].
    pub fn construct(config: Pow5Config<F, WIDTH, RATE>) -> Self {
        Pow5Chip { config }
    }
}

impl<F: Field, const WIDTH: usize, const RATE: usize> Chip<F> for Pow5Chip<F, WIDTH, RATE> {
    type Config = Pow5Config<F, WIDTH, RATE>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field, S: Spec<F, WIDTH, RATE>, const WIDTH: usize, const RATE: usize>
    PoseidonInstructions<F, S, WIDTH, RATE> for Pow5Chip<F, WIDTH, RATE>
{
    type Word = StateWord<F>;

    fn permute(
        &self,
        layouter: &mut impl Layouter<F>,
        initial_state: &State<Self::Word, WIDTH>,
    ) -> Result<State<Self::Word, WIDTH>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "permute state",
            |mut region| {
                // Load the initial state into this region.
                let state = Pow5State::load(&mut region, config, initial_state)?;

                let state: Pow5State<F, WIDTH> = (0..config.pre_rounds)
                    .try_fold(state, |res, r| res.pre_round(&mut region, config, r, r))?;

                let state = (0..config.half_full_rounds).try_fold(state, |res, r| {
                    res.full_round(
                        &mut region,
                        config,
                        config.pre_rounds + r,
                        config.pre_rounds + r,
                    )
                })?;

                let state = (0..config.partial_rounds).try_fold(state, |res, r| {
                    res.partial_round(
                        &mut region,
                        config,
                        config.pre_rounds + config.half_full_rounds + r,
                        config.pre_rounds + config.half_full_rounds + r,
                    )
                })?;

                let state = (0..config.half_full_rounds).try_fold(state, |res, r| {
                    res.full_round(
                        &mut region,
                        config,
                        config.pre_rounds + config.half_full_rounds + config.partial_rounds + r,
                        config.pre_rounds + config.half_full_rounds + config.partial_rounds + r,
                    )
                })?;

                Ok(state.0)
            },
        )
    }
}

impl<
        F: Field,
        S: Spec<F, WIDTH, RATE>,
        D: Domain<F, RATE>,
        const WIDTH: usize,
        const RATE: usize,
    > PoseidonSpongeInstructions<F, S, D, WIDTH, RATE> for Pow5Chip<F, WIDTH, RATE>
{
    fn initial_state(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<State<Self::Word, WIDTH>, Error> {
        let config = self.config();
        let state = layouter.assign_region(
            || format!("initial state for domain {}", D::name()),
            |mut region| {
                let mut state = Vec::with_capacity(WIDTH);
                let mut load_state_word = |i: usize, value: F| -> Result<_, Error> {
                    let var = region.assign_advice_from_constant(
                        || format!("state_{i}"),
                        config.state[i],
                        0,
                        value,
                    )?;
                    state.push(StateWord(var));

                    Ok(())
                };

                for i in 0..RATE {
                    load_state_word(i, F::ZERO)?;
                }
                load_state_word(RATE, D::initial_capacity_element())?;

                Ok(state)
            },
        )?;

        Ok(state.try_into().unwrap())
    }

    fn add_input(
        &self,
        layouter: &mut impl Layouter<F>,
        initial_state: &State<Self::Word, WIDTH>,
        input: &Absorbing<PaddedWord<F>, RATE>,
    ) -> Result<State<Self::Word, WIDTH>, Error> {
        let config = self.config();
        layouter.assign_region(
            || format!("add input for domain {}", D::name()),
            |mut region| {
                config.s_pad_and_add.enable(&mut region, 1)?;

                // Load the initial state into this region.
                let load_state_word = |i: usize| {
                    initial_state[i]
                        .0
                        .copy_advice(
                            || format!("load state_{i}"),
                            &mut region,
                            config.state[i],
                            0,
                        )
                        .map(StateWord)
                };
                let initial_state: Result<Vec<_>, Error> =
                    (0..WIDTH).map(load_state_word).collect();
                let initial_state = initial_state?;

                // Load the input into this region.
                let load_input_word = |i: usize| {
                    let constraint_var = match input.0[i].clone() {
                        Some(PaddedWord::Message(word)) => word,
                        Some(PaddedWord::Padding(_padding_value)) => {
                            panic!();
                            #[allow(unreachable_code)]
                            region.assign_fixed(
                                || format!("load pad_{i}"),
                                config.rc[i],
                                1,
                                || Value::known(_padding_value),
                            )?
                        }
                        _ => panic!("Input is not padded"),
                    };
                    constraint_var
                        .copy_advice(
                            || format!("load input_{i}"),
                            &mut region,
                            config.state[i],
                            1,
                        )
                        .map(StateWord)
                };
                let input: Result<Vec<_>, Error> = (0..RATE).map(load_input_word).collect();
                let input = input?;

                // Constrain the output.
                let constrain_output_word = |i: usize| {
                    let value = initial_state[i].0.value().copied()
                        + input
                            .get(i)
                            .map(|word| word.0.value().cloned())
                            // The capacity element is never altered by the input.
                            .unwrap_or_else(|| Value::known(F::ZERO));
                    region
                        .assign_advice(|| format!("load output_{i}"), config.state[i], 2, || value)
                        .map(StateWord)
                };

                let output: Result<Vec<_>, Error> = (0..WIDTH).map(constrain_output_word).collect();
                output.map(|output| output.try_into().unwrap())
            },
        )
    }

    fn get_output(state: &State<Self::Word, WIDTH>) -> Squeezing<Self::Word, RATE> {
        Squeezing(
            state[..RATE]
                .iter()
                .map(|word| Some(word.clone()))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }
}

/// A word in the Poseidon state.
#[derive(Clone, Debug)]
pub struct StateWord<F: Field>(AssignedCell<F, F>);

impl<F: Field> From<StateWord<F>> for AssignedCell<F, F> {
    fn from(state_word: StateWord<F>) -> AssignedCell<F, F> {
        state_word.0
    }
}

impl<F: Field> From<AssignedCell<F, F>> for StateWord<F> {
    fn from(cell_value: AssignedCell<F, F>) -> StateWord<F> {
        StateWord(cell_value)
    }
}

impl<F: Field> Var<F> for StateWord<F> {
    fn cell(&self) -> Cell {
        self.0.cell()
    }

    fn value(&self) -> Value<F> {
        self.0.value().cloned()
    }
}

impl<F: Field, const WIDTH: usize> Pow5State<F, WIDTH> {
    fn matmul_4(&self, mut input: Vec<Value<F>>) -> Vec<Value<F>> {
        for i in (0..WIDTH).step_by(4) {
            let t_0 = input[i] + input[i + 1]; // a + b

            let t_1 = input[i + 2] + input[i + 3]; // c + d

            let mut t_2: Value<_> = input[i + 1]; // b
            t_2 = t_2 * Value::known(F::ONE + F::ONE) + t_1; // 2b + c + d

            let mut t_3: Value<_> = input[i + 3]; // d
            t_3 = t_3 * Value::known(F::ONE + F::ONE) + t_0; // 2d + a + b

            let mut t_4: Value<_> = t_1; // c + d
            t_4 = t_4 * Value::known(F::ONE + F::ONE) * Value::known(F::ONE + F::ONE) + t_3; // a + b + 4c + 6d

            let mut t_5: Value<_> = t_0; // a + b
            t_5 = t_5 * Value::known(F::ONE + F::ONE) * Value::known(F::ONE + F::ONE) + t_2; // 4a + 6b + c + d

            input[i] = t_3 + t_5; // 5a + 7b + c + 3d
            input[i + 1] = t_5; // 4a + 6b + c + d
            input[i + 2] = t_2 + t_4; // a + 3b + 5c + 7d
            input[i + 3] = t_4; // a + b + 4c + 6d
        }
        input
    }

    fn matmul_full(&self, input: Vec<Value<F>>) -> [Value<F>; WIDTH] {
        match WIDTH {
            3 => {
                let mut sum = Value::known(F::ZERO);
                sum = sum + input[0];
                sum = sum + input[1];
                sum = sum + input[2];

                input
                    .into_iter()
                    .map(|r| r + sum)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            }
            4 => self.matmul_4(input).try_into().unwrap(),
            8 | 12 | 16 | 20 => {
                let input = self.matmul_4(input);
                let mut sum = [Value::known(F::ZERO); 4];
                for i in 0..4 {
                    sum[i] = input[i];
                    for j in (4..WIDTH).step_by(4) {
                        sum[i] = sum[i] + input[j + i];
                    }
                }
                input
                    .into_iter()
                    .enumerate()
                    .map(|(i, r)| r + sum[i % 4])
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            }
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug)]
struct Pow5State<F: Field, const WIDTH: usize>([StateWord<F>; WIDTH]);

impl<F: Field, const WIDTH: usize> Pow5State<F, WIDTH> {
    fn pre_round<const RATE: usize>(
        self,
        region: &mut Region<F>,
        config: &Pow5Config<F, WIDTH, RATE>,
        round: usize,
        offset: usize,
    ) -> Result<Self, Error> {
        Self::round(region, config, round, offset, config.s_pre, |region| {
            let r: Vec<Value<F>> = self
                .0
                .iter()
                .map(|word| word.0.value().map(|v| *v))
                .collect();

            let sum = r
                .clone()
                .into_iter()
                .fold(Value::known(F::ZERO), |acc, v| acc + v);

            region.assign_advice(|| format!("round_{round} sum"), config.sum, offset, || sum)?;

            Ok((round + 1, self.matmul_full(r)))
        })
    }

    fn full_round<const RATE: usize>(
        self,
        region: &mut Region<F>,
        config: &Pow5Config<F, WIDTH, RATE>,
        round: usize,
        offset: usize,
    ) -> Result<Self, Error> {
        Self::round(region, config, round, offset, config.s_full, |region| {
            let q = self.0.iter().enumerate().map(|(idx, word)| {
                word.0
                    .value()
                    .map(|v| *v + config.round_constants[round - 1][idx])
            });
            let r: Vec<_> = q.map(|q| q.map(|q| q.pow(config.alpha))).collect();

            let sum = r
                .clone()
                .into_iter()
                .fold(Value::known(F::ZERO), |acc, v| acc + v);

            region.assign_advice(|| format!("round_{round} sum"), config.sum, offset, || sum)?;

            Ok((round + 1, self.matmul_full(r)))
        })
    }

    fn partial_round<const RATE: usize>(
        self,
        region: &mut Region<F>,
        config: &Pow5Config<F, WIDTH, RATE>,
        round: usize,
        offset: usize,
    ) -> Result<Self, Error> {
        Self::round(region, config, round, offset, config.s_partial, |region| {
            let q: Value<Vec<_>> = self.0.iter().map(|word| word.0.value().cloned()).collect();

            let r: Value<Vec<_>> = q.map(|q| {
                let r_0 = (q[0] + config.round_constants[round - 1][0]).pow(config.alpha);
                let r_i = q[1..].iter().copied();
                std::iter::empty().chain(Some(r_0)).chain(r_i).collect()
            });

            let sum = r.clone().map(|r| r.iter().fold(F::ZERO, |acc, v| acc + v));

            region.assign_advice(|| format!("round_{round} sum"), config.sum, offset, || sum)?;

            let state: Vec<Value<F>> = r
                .transpose_vec(WIDTH)
                .into_iter()
                .enumerate()
                .map(|(i, r)| r * Value::known(config.diag[i]) + sum)
                .collect();

            Ok((round + 1, state.try_into().unwrap()))
        })
    }

    fn load<const RATE: usize>(
        region: &mut Region<F>,
        config: &Pow5Config<F, WIDTH, RATE>,
        initial_state: &State<StateWord<F>, WIDTH>,
    ) -> Result<Self, Error> {
        let load_state_word = |i: usize| {
            initial_state[i]
                .0
                .copy_advice(|| format!("load state_{i}"), region, config.state[i], 0)
                .map(StateWord)
        };

        let state: Result<Vec<_>, _> = (0..WIDTH).map(load_state_word).collect();
        state.map(|state| Pow5State(state.try_into().unwrap()))
    }

    fn round<const RATE: usize>(
        region: &mut Region<F>,
        config: &Pow5Config<F, WIDTH, RATE>,
        round: usize,
        offset: usize,
        round_gate: Selector,
        round_fn: impl FnOnce(&mut Region<F>) -> Result<(usize, [Value<F>; WIDTH]), Error>,
    ) -> Result<Self, Error> {
        // Enable the required gate.
        round_gate.enable(region, offset)?;

        // Load the round constants.
        let mut load_round_constant = |i: usize| {
            region.assign_fixed(
                || format!("round_{round} rc_{i}"),
                config.rc[i],
                offset,
                || Value::known(config.round_constants[round - 1][i]),
            )
        };

        let partial_rounds_begin = config.pre_rounds + config.half_full_rounds;
        let partial_rounds_end = partial_rounds_begin + config.partial_rounds;

        if round < config.pre_rounds {
            // No constants are used in the preliminary round.
        } else if (partial_rounds_begin..partial_rounds_end).contains(&round) {
            load_round_constant(0)?;
        } else {
            // Full round.
            for i in 0..WIDTH {
                load_round_constant(i)?;
            }
        }

        // Compute the next round's state.
        let (next_round, next_state) = round_fn(region)?;

        let next_state_word = |i: usize| {
            let value = next_state[i];
            let var = region.assign_advice(
                || format!("round_{next_round} state_{i}"),
                config.state[i],
                offset + 1,
                || value,
            )?;
            Ok(StateWord(var))
        };

        let next_state: Result<Vec<_>, _> = (0..WIDTH).map(next_state_word).collect();
        next_state.map(|next_state| Pow5State(next_state.try_into().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use group::ff::{Field, PrimeField};
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use halo2curves::pasta::{pallas, Fp};
    use rand::rngs::OsRng;

    use super::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord};
    use crate::poseidon::{
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    };
    use std::convert::TryInto;
    use std::marker::PhantomData;

    struct PermuteCircuit<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize>(
        PhantomData<S>,
    );

    impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize> Circuit<Fp>
        for PermuteCircuit<S, WIDTH, RATE>
    {
        type Config = Pow5Config<Fp, WIDTH, RATE>;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            PermuteCircuit::<S, WIDTH, RATE>(PhantomData)
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Pow5Config<Fp, WIDTH, RATE> {
            let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
            let sum = meta.advice_column();

            let rc = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

            Pow5Chip::configure::<S>(meta, state.try_into().unwrap(), rc.try_into().unwrap(), sum)
        }

        fn synthesize(
            &self,
            config: Pow5Config<Fp, WIDTH, RATE>,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let initial_state = layouter.assign_region(
                || "prepare initial state",
                |mut region| {
                    let state_word = |i: usize| {
                        let value = Value::known(Fp::from(i as u64));
                        let var = region.assign_advice(
                            || format!("load state_{}", i),
                            config.state[i],
                            0,
                            || value,
                        )?;
                        Ok(StateWord(var))
                    };

                    let state: Result<Vec<_>, Error> = (0..WIDTH).map(state_word).collect();
                    Ok(state?.try_into().unwrap())
                },
            )?;

            let chip = Pow5Chip::construct(config.clone());
            let final_state = <Pow5Chip<_, WIDTH, RATE> as PoseidonInstructions<
                Fp,
                S,
                WIDTH,
                RATE,
            >>::permute(&chip, &mut layouter, &initial_state)?;

            // For the purpose of this test, compute the real final state inline.
            let mut expected_final_state = (0..WIDTH)
                .map(|idx| Fp::from(idx as u64))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let (round_constants, mds_full, mds_partial) = S::constants();
            poseidon::permute::<_, S, WIDTH, RATE>(
                &mut expected_final_state,
                &mds_full,
                &mds_partial,
                &round_constants,
            );

            layouter.assign_region(
                || "constrain final state",
                |mut region| {
                    let mut final_state_word = |i: usize| {
                        let var = region.assign_advice(
                            || format!("load final_state_{}", i),
                            config.state[i],
                            0,
                            || Value::known(expected_final_state[i]),
                        )?;
                        region.constrain_equal(final_state[i].0.cell(), var.cell())
                    };

                    for i in 0..(WIDTH) {
                        final_state_word(i)?;
                    }

                    Ok(())
                },
            )
        }
    }

    #[test]
    fn poseidon_permute() {
        let k = 6;
        let circuit = PermuteCircuit::<OrchardNullifier, 3, 2>(PhantomData);
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()))
    }

    struct HashCircuit<
        S: Spec<Fp, WIDTH, RATE>,
        const WIDTH: usize,
        const RATE: usize,
        const L: usize,
    > {
        message: Value<[Fp; L]>,
        // For the purpose of this test, witness the result.
        // TODO: Move this into an instance column.
        output: Value<Fp>,
        _spec: PhantomData<S>,
    }

    impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize>
        Circuit<Fp> for HashCircuit<S, WIDTH, RATE, L>
    {
        type Config = Pow5Config<Fp, WIDTH, RATE>;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self {
                message: Value::unknown(),
                output: Value::unknown(),
                _spec: PhantomData,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Pow5Config<Fp, WIDTH, RATE> {
            let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
            let sum = meta.advice_column();

            let rc = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

            Pow5Chip::configure::<S>(meta, state.try_into().unwrap(), rc.try_into().unwrap(), sum)
        }

        fn synthesize(
            &self,
            config: Pow5Config<Fp, WIDTH, RATE>,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = Pow5Chip::construct(config.clone());

            let message = layouter.assign_region(
                || "load message",
                |mut region| {
                    let message_word = |i: usize| {
                        let value = self.message.map(|message_vals| message_vals[i]);
                        region.assign_advice(
                            || format!("load message_{}", i),
                            config.state[i],
                            0,
                            || value,
                        )
                    };

                    let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
                    Ok(message?.try_into().unwrap())
                },
            )?;

            let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
                chip,
                layouter.namespace(|| "init"),
            )?;
            let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

            layouter.assign_region(
                || "constrain output",
                |mut region| {
                    let expected_var = region.assign_advice(
                        || "load output",
                        config.state[0],
                        0,
                        || self.output,
                    )?;
                    region.constrain_equal(output.cell(), expected_var.cell())
                },
            )
        }
    }

    #[test]
    fn poseidon_hash() {
        let rng = OsRng;

        let message = [Fp::random(rng), Fp::random(rng)];
        let output =
            poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);

        let k = 6;
        let circuit = HashCircuit::<OrchardNullifier, 3, 2, 2> {
            message: Value::known(message),
            output: Value::known(output),
            _spec: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()))
    }

    #[test]
    fn poseidon_hash_longer_input() {
        let rng = OsRng;

        let message = [Fp::random(rng), Fp::random(rng), Fp::random(rng)];
        let output =
            poseidon::Hash::<_, OrchardNullifier, ConstantLength<3>, 3, 2>::init().hash(message);

        let k = 7;
        let circuit = HashCircuit::<OrchardNullifier, 3, 2, 3> {
            message: Value::known(message),
            output: Value::known(output),
            _spec: PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()))
    }

    #[test]
    fn hash_test_vectors() {
        for tv in crate::poseidon::primitives::test_vectors::fp::hash() {
            let message = [
                pallas::Base::from_repr(tv.input[0]).unwrap(),
                pallas::Base::from_repr(tv.input[1]).unwrap(),
            ];
            let output = poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init()
                .hash(message);

            let k = 6;
            let circuit = HashCircuit::<OrchardNullifier, 3, 2, 2> {
                message: Value::known(message),
                output: Value::known(output),
                _spec: PhantomData,
            };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    #[cfg(feature = "test-dev-graph")]
    #[test]
    fn print_poseidon_chip() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("poseidon-chip-layout.png", (1024, 768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Poseidon Chip Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = HashCircuit::<OrchardNullifier, 3, 2, 2> {
            message: Value::unknown(),
            output: Value::unknown(),
            _spec: PhantomData,
        };
        halo2_proofs::dev::CircuitLayout::default()
            .render(6, &circuit, &root)
            .unwrap();
    }
}
