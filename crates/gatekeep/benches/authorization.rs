//! Small reproducible timings; no database, runtime or compiler time is included.
use gatekeep::{
    Fact, KnownFacts, Lattice, PolicyId, PreparedPolicy, StaticFactId, condition, evaluate, policy,
};
use serde::Serialize;
use std::{error::Error, hint::black_box, time::Instant};

struct Owner;
impl Fact for Owner {
    const ID: StaticFactId = StaticFactId::new("owner");
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
enum Tier {
    Shared,
    Full,
}
impl Lattice for Tier {
    fn meet(&self, other: &Self) -> Self {
        self.min(other).clone()
    }
    fn join(&self, other: &Self) -> Self {
        self.max(other).clone()
    }
    fn top() -> Self {
        Self::Full
    }
    fn bottom() -> Self {
        Self::Shared
    }
}

fn measure(label: &str, mut operation: impl FnMut()) {
    let started = Instant::now();
    for _ in 0..100_000 {
        operation();
    }
    println!("{label}: {:?} / 100000 iterations", started.elapsed());
}

fn main() -> Result<(), Box<dyn Error>> {
    let boolean = policy::grant_clause((), condition::has::<Owner>()).into_policy();
    let graded = policy::any([
        policy::permit(Tier::Shared),
        policy::grant_clause(Tier::Full, condition::has::<Owner>()).into_policy(),
    ]);
    let facts = KnownFacts::new().with_bool::<Owner>(true);
    let id = PolicyId::new("read")?;
    let prepared = PreparedPolicy::new(id.clone(), graded.clone())?;
    measure("boolean evaluation with trace", || {
        black_box(evaluate(black_box(&boolean), black_box(&facts)));
    });
    measure("graded evaluation with trace", || {
        black_box(evaluate(black_box(&graded), black_box(&facts)));
    });
    let decision = evaluate(&graded, &facts);
    measure("durable trace conversion", || {
        let _result = black_box(decision.to_trace());
    });
    measure("policy hash", || {
        let _result = black_box(graded.hash());
    });
    measure("policy preparation", || {
        let _result = black_box(PreparedPolicy::new(id.clone(), graded.clone()));
    });
    measure("prepared metadata borrow", || {
        black_box((prepared.anchor(), prepared.required_facts()));
    });
    Ok(())
}
