//! `SQLx` lowering for gatekeep residual policies.
//!
//! This crate lowers a `gatekeep::ResidualPolicy` into trusted SQL fragments
//! that can be appended to a `sqlx::QueryBuilder`.

#![forbid(unsafe_code)]

#[cfg(not(any(feature = "postgres", feature = "sqlite", feature = "mysql")))]
compile_error!(
    "gatekeep-sqlx requires at least one SQLx backend feature: postgres, sqlite, or mysql"
);

use std::marker::PhantomData;

use gatekeep::{
    Condition, Context, FactId, LowerError, Lowered, QueryLowering, ResidualPolicy,
    ResidualPolicyBranch, ResidualPolicyNode,
};

mod fragment;

#[cfg(feature = "mysql")]
pub use fragment::MySqlBackend;
#[cfg(feature = "sqlite")]
pub use fragment::SqliteBackend;
pub use fragment::{
    GatekeepSqlxBackend, SqlxDriver, SqlxDriverError, SqlxFragment, SqlxValue,
    infer_enabled_driver_from_url, validate_database_url_for_backend,
};
#[cfg(feature = "postgres")]
pub use fragment::{PgFragment, PgValue, PostgresBackend};

/// Maps a residual fact to a trusted predicate over the candidate row.
pub trait SqlxFactPredicates<B>
where
    B: GatekeepSqlxBackend,
{
    /// Returns a predicate for the given fact, or `None` when the fact cannot be
    /// represented by this backend.
    fn predicate(&self, fact: &FactId, cx: &Context) -> Option<SqlxFragment<B>>;
}

/// Maps a residual fact to a trusted Postgres predicate over the candidate row.
#[cfg(feature = "postgres")]
pub trait PgFactPredicates {
    /// Returns a predicate for the given fact, or `None` when the fact cannot be
    /// represented by this backend.
    fn predicate(&self, fact: &FactId, cx: &Context) -> Option<PgFragment>;
}

#[cfg(feature = "postgres")]
impl<T> SqlxFactPredicates<PostgresBackend> for T
where
    T: PgFactPredicates,
{
    fn predicate(&self, fact: &FactId, cx: &Context) -> Option<SqlxFragment<PostgresBackend>> {
        PgFactPredicates::predicate(self, fact, cx)
    }
}

/// Maps a policy outcome to a total-order SQL ordinal.
pub trait SqlOutcome {
    /// Returns the scalar ordinal used by SQL grade projection.
    fn to_sql_ordinal(&self) -> i64;
}

impl SqlOutcome for () {
    fn to_sql_ordinal(&self) -> i64 {
        0
    }
}

/// Projection strategy for turning outcomes into SQL fragments.
pub trait OutcomeProjection<B, O>
where
    B: GatekeepSqlxBackend,
{
    /// Builds a SQL fragment for a constant outcome.
    fn constant(&self, outcome: &O) -> Result<SqlxFragment<B>, LowerError>;
}

/// Outcome projection backed by [`SqlOutcome`].
#[derive(Clone, Copy, Debug, Default)]
pub struct OrdinalProjection;

impl<B, O> OutcomeProjection<B, O> for OrdinalProjection
where
    B: GatekeepSqlxBackend,
    O: SqlOutcome,
{
    fn constant(&self, outcome: &O) -> Result<SqlxFragment<B>, LowerError> {
        Ok(SqlxFragment::bind(outcome.to_sql_ordinal()))
    }
}

/// Projection that rejects grade lowering.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoGradeProjection;

impl<B, O> OutcomeProjection<B, O> for NoGradeProjection
where
    B: GatekeepSqlxBackend,
{
    fn constant(&self, _outcome: &O) -> Result<SqlxFragment<B>, LowerError> {
        Err(LowerError::NonTotalGrade)
    }
}

/// `SQLx` lowerer for gatekeep residual policies.
#[derive(Clone, Debug)]
pub struct SqlxLowerer<B, P, M = OrdinalProjection> {
    predicates: P,
    projection: M,
    backend: PhantomData<fn() -> B>,
}

/// Postgres lowerer for gatekeep residual policies.
#[cfg(feature = "postgres")]
pub type PgLowerer<P, M = OrdinalProjection> = SqlxLowerer<PostgresBackend, P, M>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SqlxLowered<B> {
    filter: SqlxFragment<B>,
    grade: SqlxFragment<B>,
}

impl<B, P> SqlxLowerer<B, P, OrdinalProjection>
where
    B: GatekeepSqlxBackend,
{
    /// Builds a lowerer using ordinal grade projection.
    #[must_use]
    pub const fn new(predicates: P) -> Self {
        Self::with_projection(predicates, OrdinalProjection)
    }
}

impl<B, P, M> SqlxLowerer<B, P, M>
where
    B: GatekeepSqlxBackend,
{
    /// Builds a lowerer using a caller-supplied projection strategy.
    #[must_use]
    pub const fn with_projection(predicates: P, projection: M) -> Self {
        Self {
            predicates,
            projection,
            backend: PhantomData,
        }
    }

    /// Lowers only the Boolean filter. This works for every outcome lattice.
    pub fn lower_filter<O>(
        &self,
        residual: &ResidualPolicy<O>,
        cx: &Context,
    ) -> Result<SqlxFragment<B>, LowerError>
    where
        P: SqlxFactPredicates<B>,
    {
        residual.try_fold_pruned(
            &mut |branch| match branch {
                ResidualPolicyBranch::OrElseFallback { fallback, .. } => {
                    !fallback.carries_obligation()
                }
            },
            &mut |node| self.lower_filter_node(node, cx),
        )
    }

    fn lower_filter_node<O>(
        &self,
        node: ResidualPolicyNode<'_, O, SqlxFragment<B>>,
        cx: &Context,
    ) -> Result<SqlxFragment<B>, LowerError>
    where
        P: SqlxFactPredicates<B>,
    {
        match node {
            ResidualPolicyNode::Permit(_) | ResidualPolicyNode::PermitWithTrace { .. } => {
                Ok(SqlxFragment::trusted("TRUE"))
            }
            ResidualPolicyNode::Deny | ResidualPolicyNode::DenyWithTrace { .. } => {
                Ok(SqlxFragment::trusted("FALSE"))
            }
            ResidualPolicyNode::Grant { condition, .. } => self.lower_condition(condition, cx),
            ResidualPolicyNode::All { arms, .. } => Ok(fragment_set(arms, " AND ", "FALSE")),
            ResidualPolicyNode::Any { arms, .. } => Ok(fragment_set(arms, " OR ", "FALSE")),
            ResidualPolicyNode::OrElse {
                fallback_policy,
                primary,
                fallback,
                ..
            } => {
                if fallback_policy.carries_obligation() {
                    Ok(primary)
                } else {
                    Ok(match fallback {
                        Some(fallback) => SqlxFragment::binary(" OR ", vec![primary, fallback]),
                        None => primary,
                    })
                }
            }
        }
    }

    fn lower_condition(
        &self,
        condition: &Condition,
        cx: &Context,
    ) -> Result<SqlxFragment<B>, LowerError>
    where
        P: SqlxFactPredicates<B>,
    {
        match condition {
            Condition::Always => Ok(SqlxFragment::trusted("TRUE")),
            Condition::Never => Ok(SqlxFragment::trusted("FALSE")),
            Condition::Has(fact) => self
                .predicates
                .predicate(fact, cx)
                .map(is_true)
                .ok_or_else(|| LowerError::Unlowerable(fact.clone())),
            Condition::Not(inner) => Ok(SqlxFragment::unary(
                "NOT ",
                self.lower_condition(inner, cx)?,
            )),
            Condition::All(conditions) => {
                lower_condition_set(conditions, " AND ", "FALSE", |item| {
                    self.lower_condition(item, cx)
                })
            }
            Condition::Any(conditions) => {
                lower_condition_set(conditions, " OR ", "FALSE", |item| {
                    self.lower_condition(item, cx)
                })
            }
        }
    }

    fn lower_policy<O>(
        &self,
        residual: &ResidualPolicy<O>,
        cx: &Context,
    ) -> Result<SqlxLowered<B>, LowerError>
    where
        P: SqlxFactPredicates<B>,
        M: OutcomeProjection<B, O>,
    {
        residual.try_fold_pruned(
            &mut |branch| match branch {
                ResidualPolicyBranch::OrElseFallback { fallback, .. } => {
                    !fallback.carries_obligation()
                }
            },
            &mut |node| self.lower_node(node, cx),
        )
    }

    fn lower_node<O>(
        &self,
        node: ResidualPolicyNode<'_, O, SqlxLowered<B>>,
        cx: &Context,
    ) -> Result<SqlxLowered<B>, LowerError>
    where
        P: SqlxFactPredicates<B>,
        M: OutcomeProjection<B, O>,
    {
        match node {
            ResidualPolicyNode::Permit(outcome)
            | ResidualPolicyNode::PermitWithTrace { outcome, .. } => Ok(SqlxLowered {
                filter: SqlxFragment::trusted("TRUE"),
                grade: self.projection.constant(outcome)?,
            }),
            ResidualPolicyNode::Deny | ResidualPolicyNode::DenyWithTrace { .. } => {
                Ok(SqlxLowered {
                    filter: SqlxFragment::trusted("FALSE"),
                    grade: SqlxFragment::trusted("NULL"),
                })
            }
            ResidualPolicyNode::Grant {
                outcome, condition, ..
            } => {
                let filter = self.lower_condition(condition, cx)?;
                let outcome = self.projection.constant(outcome)?;
                Ok(SqlxLowered {
                    filter: filter.clone(),
                    grade: case_when(filter, outcome, SqlxFragment::trusted("NULL")),
                })
            }
            ResidualPolicyNode::All { arms, .. } => {
                let (filters, grades) = unzip_lowered(arms);
                Ok(SqlxLowered {
                    filter: fragment_set(filters, " AND ", "FALSE"),
                    grade: grade_set::<B>(grades, B::MIN_FUNCTION),
                })
            }
            ResidualPolicyNode::Any { arms, .. } => {
                let (filters, grades) = unzip_lowered(arms);
                Ok(SqlxLowered {
                    filter: fragment_set(filters, " OR ", "FALSE"),
                    grade: grade_set::<B>(grades, B::MAX_FUNCTION),
                })
            }
            ResidualPolicyNode::OrElse {
                fallback_policy,
                primary,
                fallback,
                ..
            } => {
                if fallback_policy.carries_obligation() {
                    return Ok(primary);
                }

                Ok(match fallback {
                    Some(fallback) => SqlxLowered {
                        filter: SqlxFragment::binary(
                            " OR ",
                            vec![primary.filter.clone(), fallback.filter],
                        ),
                        grade: case_when(primary.filter, primary.grade, fallback.grade),
                    },
                    None => primary,
                })
            }
        }
    }
}

impl<O, B, P, M> QueryLowering<O> for SqlxLowerer<B, P, M>
where
    B: GatekeepSqlxBackend,
    P: SqlxFactPredicates<B>,
    M: OutcomeProjection<B, O>,
{
    type Filter = SqlxFragment<B>;
    type Projection = SqlxFragment<B>;

    fn lower(
        &self,
        residual: &ResidualPolicy<O>,
        cx: &Context,
    ) -> Result<Lowered<Self::Filter, Self::Projection>, LowerError> {
        let lowered = self.lower_policy(residual, cx)?;
        Ok(Lowered {
            filter: lowered.filter,
            grade: lowered.grade,
        })
    }
}

fn lower_condition_set<B>(
    conditions: &[Condition],
    separator: &str,
    empty: &str,
    lower: impl FnMut(&Condition) -> Result<SqlxFragment<B>, LowerError>,
) -> Result<SqlxFragment<B>, LowerError> {
    if conditions.is_empty() {
        return Ok(SqlxFragment::trusted(empty));
    }
    let fragments = conditions
        .iter()
        .map(lower)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SqlxFragment::binary(separator, fragments))
}

fn fragment_set<B>(
    fragments: Vec<SqlxFragment<B>>,
    separator: &str,
    empty: &str,
) -> SqlxFragment<B> {
    if fragments.is_empty() {
        SqlxFragment::trusted(empty)
    } else {
        SqlxFragment::binary(separator, fragments)
    }
}

fn grade_set<B>(grades: Vec<SqlxFragment<B>>, function: &str) -> SqlxFragment<B>
where
    B: GatekeepSqlxBackend,
{
    match grades.len() {
        0 => SqlxFragment::trusted("NULL"),
        1 => grades
            .into_iter()
            .next()
            .unwrap_or_else(|| SqlxFragment::trusted("NULL")),
        _ if B::GRADE_FUNCTION_PROPAGATES_NULL => {
            let mut iter = grades.into_iter();
            let mut combined = iter.next().unwrap_or_else(|| SqlxFragment::trusted("NULL"));
            for grade in iter {
                combined = null_safe_grade_pair(function, combined, grade);
            }
            combined
        }
        _ => SqlxFragment::function(function, grades),
    }
}

fn null_safe_grade_pair<B>(
    function: &str,
    left: SqlxFragment<B>,
    right: SqlxFragment<B>,
) -> SqlxFragment<B> {
    let mut fragment = SqlxFragment::trusted("CASE WHEN ");
    fragment.push_fragment(left.clone().wrapped());
    fragment.push_sql(" IS NULL THEN ");
    fragment.push_fragment(right.clone());
    fragment.push_sql(" WHEN ");
    fragment.push_fragment(right.clone().wrapped());
    fragment.push_sql(" IS NULL THEN ");
    fragment.push_fragment(left.clone());
    fragment.push_sql(" ELSE ");
    fragment.push_fragment(SqlxFragment::function(function, vec![left, right]));
    fragment.push_sql(" END");
    fragment
}

fn unzip_lowered<B>(lowered: Vec<SqlxLowered<B>>) -> (Vec<SqlxFragment<B>>, Vec<SqlxFragment<B>>) {
    lowered
        .into_iter()
        .map(|lowered| (lowered.filter, lowered.grade))
        .unzip()
}

fn case_when<B>(
    condition: SqlxFragment<B>,
    then_expr: SqlxFragment<B>,
    else_expr: SqlxFragment<B>,
) -> SqlxFragment<B> {
    let mut fragment = SqlxFragment::trusted("CASE WHEN ");
    fragment.push_fragment(condition);
    fragment.push_sql(" THEN ");
    fragment.push_fragment(then_expr);
    fragment.push_sql(" ELSE ");
    fragment.push_fragment(else_expr);
    fragment.push_sql(" END");
    fragment
}

fn is_true<B>(predicate: SqlxFragment<B>) -> SqlxFragment<B> {
    let mut fragment = SqlxFragment::trusted("(");
    fragment.push_fragment(predicate);
    fragment.push_sql(") IS TRUE");
    fragment
}
