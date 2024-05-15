use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Instance,
    },
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
        },
        VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};

use halo2_poseidon::poseidon::{
    primitives::{self as poseidon, generate_constants, ConstantLength, Mds, Spec},
    Hash, Pow5Chip, Pow5Config,
};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2curves::bn256::{Bn256, Fr};
use std::convert::TryInto;
use std::marker::PhantomData;

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

#[derive(Clone, Copy)]
struct HashCircuit<S, const WIDTH: usize, const RATE: usize, const L: usize>
where
    S: Spec<Fr, WIDTH, RATE> + Clone + Copy,
{
    message: Value<[Fr; L]>,
    _spec: PhantomData<S>,
}

#[derive(Debug, Clone)]
struct MyConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
    input: [Column<Advice>; L],
    expected: Column<Instance>,
    poseidon_config: Pow5Config<Fr, WIDTH, RATE>,
}

impl<S, const WIDTH: usize, const RATE: usize, const L: usize> Circuit<Fr>
    for HashCircuit<S, WIDTH, RATE, L>
where
    S: Spec<Fr, WIDTH, RATE> + Copy + Clone,
{
    type Config = MyConfig<WIDTH, RATE, L>;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            message: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let expected = meta.instance_column();
        meta.enable_equality(expected);

        let rc = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let sum = meta.advice_column();

        Self::Config {
            input: state[..RATE].try_into().unwrap(),
            expected,
            poseidon_config: Pow5Chip::configure::<S>(
                meta,
                state.try_into().unwrap(),
                rc.try_into().unwrap(),
                sum,
            ),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let chip = Pow5Chip::construct(config.poseidon_config.clone());

        let message = layouter.assign_region(
            || "load message",
            |mut region| {
                let message_word = |i: usize| {
                    let value = self.message.map(|message_vals| message_vals[i]);
                    region.assign_advice(
                        || format!("load message_{}", i),
                        config.input[i],
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

        layouter.constrain_instance(output.cell(), config.expected, 0)
    }
}

#[derive(Debug, Clone, Copy)]
struct MySpec<const WIDTH: usize, const RATE: usize>;

impl<const WIDTH: usize, const RATE: usize> Spec<Fr, WIDTH, RATE> for MySpec<WIDTH, RATE> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fr) -> Fr {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        0
    }

    fn constants() -> (Vec<[Fr; WIDTH]>, Mds<Fr, WIDTH>, Mds<Fr, WIDTH>) {
        generate_constants::<_, Self, WIDTH, RATE>()
    }
}

const K: u32 = 7;

fn bench_poseidon<S, const WIDTH: usize, const RATE: usize, const L: usize>(
    name: &str,
    c: &mut Criterion,
) where
    S: Spec<Fr, WIDTH, RATE> + Copy + Clone,
{
    // Initialize the polynomial commitment parameters
    let params: ParamsKZG<Bn256> = ParamsKZG::new(K);

    let empty_circuit = HashCircuit::<S, WIDTH, RATE, L> {
        message: Value::unknown(),
        _spec: PhantomData,
    };

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let prover_name = name.to_string() + "-prover";
    let verifier_name = name.to_string() + "-verifier";

    let mut rng = OsRng;
    let message: [Fr; L] = (0..L)
        .map(|i| Fr::from_u128(i as u128))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let output = poseidon::Hash::<_, S, ConstantLength<L>, WIDTH, RATE>::init().hash(message);

    let circuit = HashCircuit::<S, WIDTH, RATE, L> {
        message: Value::known(message),
        _spec: PhantomData,
    };

    println!(
        "Proof {:?}",
        MockProver::run(K, &circuit, vec![vec![output]])
            .unwrap()
            .verify()
    );

    c.bench_function(&prover_name, |b| {
        // Create a proof
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        b.iter(|| {
            create_proof::<KZGCommitmentScheme<_>, ProverSHPLONK<_>, _, _, _, _>(
                &params,
                &pk,
                &[circuit],
                &[&[&[output]]],
                &mut rng,
                &mut transcript,
            )
            .expect("proof generation should not fail")
        })
    });

    println!(
        "Cost {:?}",
        halo2_proofs::dev::cost_model::from_circuit_to_model_circuit::<_, _, 56, 56>(
            7,
            &circuit,
            vec![vec![output]],
            halo2_proofs::dev::cost_model::CommitmentScheme::KZGSHPLONK
        )
    );

    // Create a proof
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<KZGCommitmentScheme<_>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&[output]]],
        &mut rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();

    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    println!(
        "Proof {:?}",
        verify_proof::<_, VerifierSHPLONK<_>, _, _, _>(
            &params,
            pk.get_vk(),
            strategy,
            &[&[&[output]]],
            &mut transcript
        )
    );

    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let strategy = SingleStrategy::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            assert!(verify_proof::<_, VerifierSHPLONK<_>, _, _, _>(
                &params,
                pk.get_vk(),
                strategy,
                &[&[&[output]]],
                &mut transcript
            )
            .is_ok());
        });
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_poseidon::<MySpec<3, 2>, 3, 2, 2>("WIDTH = 3, RATE = 2", c);
    bench_poseidon::<MySpec<4, 3>, 4, 3, 3>("WIDTH = 4, RATE = 3", c);
    //bench_poseidon::<MySpec<12, 11>, 12, 11, 11>("WIDTH = 12, RATE = 11", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
