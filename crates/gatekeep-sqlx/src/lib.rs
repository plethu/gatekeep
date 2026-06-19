//! `SQLx` lowering for gatekeep residual policies.
//!
//! This crate lowers a `gatekeep::ResidualPolicy` into trusted Postgres SQL
//! fragments that can be appended to a `sqlx::QueryBuilder`.

#![forbid(unsafe_code)]

use gatekeep::{
    Condition, Context, FactId, LowerError, Lowered, QueryLowering, ResidualPolicy,
    ResidualPolicyBranch, ResidualPolicyNode,
};
use sqlx::{Postgres, QueryBuilder};

/// Postgres scalar value carried by a lowered SQL fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PgValue {
    /// Boolean bind value.
    Bool(bool),
    /// Signed 64-bit integer bind value.
    I64(i64),
    /// Text bind value.
    Text(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SqlPart {
    Text(String),
    Bind(PgValue),
}

/// Trusted Postgres SQL plus ordered bind values.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PgFragment {
    parts: Vec<SqlPart>,
}

impl PgFragment {
    /// Builds a fragment from SQL owned by the application.
    ///
    /// Callers must not pass user-supplied text here. Dynamic values belong in
    /// bind fragments such as [`Self::bind_i64`] and [`Self::bind_text`].
    #[must_use]
    pub fn trusted(sql: impl Into<String>) -> Self {
        let sql = sql.into();
        if sql.is_empty() {
            Self::default()
        } else {
            Self {
                parts: vec![SqlPart::Text(sql)],
            }
        }
    }

    /// Builds a boolean bind fragment.
    #[must_use]
    pub fn bind_bool(value: bool) -> Self {
        Self::bind(PgValue::Bool(value))
    }

    /// Builds an integer bind fragment.
    #[must_use]
    pub fn bind_i64(value: i64) -> Self {
        Self::bind(PgValue::I64(value))
    }

    /// Builds a text bind fragment.
    #[must_use]
    pub fn bind_text(value: impl Into<String>) -> Self {
        Self::bind(PgValue::Text(value.into()))
    }

    /// Returns the ordered bind values.
    pub fn binds(&self) -> impl Iterator<Item = &PgValue> {
        self.parts.iter().filter_map(|part| match part {
            SqlPart::Text(_) => None,
            SqlPart::Bind(value) => Some(value),
        })
    }

    /// Appends another fragment to this one.
    pub fn push_fragment(&mut self, fragment: Self) {
        self.parts.extend(fragment.parts);
    }

    /// Converts the fragment to Postgres placeholders (`$1`, `$2`, ...).
    #[must_use]
    pub fn to_postgres_sql(&self) -> String {
        let mut sql = String::new();
        let mut placeholders = 0usize;

        for part in &self.parts {
            match part {
                SqlPart::Text(text) => sql.push_str(text),
                SqlPart::Bind(_) => {
                    placeholders += 1;
                    sql.push('$');
                    sql.push_str(&placeholders.to_string());
                }
            }
        }
        sql
    }

    /// Appends this fragment to a `SQLx` Postgres query builder.
    pub fn push_to(&self, builder: &mut QueryBuilder<Postgres>) {
        for part in &self.parts {
            match part {
                SqlPart::Text(text) => {
                    builder.push(text);
                }
                SqlPart::Bind(value) => push_bind(builder, value),
            }
        }
    }

    #[must_use]
    fn bind(value: PgValue) -> Self {
        Self {
            parts: vec![SqlPart::Bind(value)],
        }
    }

    fn push_sql(&mut self, sql: impl Into<String>) {
        let sql = sql.into();
        if !sql.is_empty() {
            self.parts.push(SqlPart::Text(sql));
        }
    }

    #[must_use]
    fn wrapped(self) -> Self {
        let mut fragment = Self::trusted("(");
        fragment.push_fragment(self);
        fragment.push_sql(")");
        fragment
    }

    #[must_use]
    fn unary(prefix: &str, inner: Self) -> Self {
        let mut fragment = Self::trusted(prefix);
        fragment.push_fragment(inner.wrapped());
        fragment
    }

    #[must_use]
    fn binary(separator: &str, fragments: Vec<Self>) -> Self {
        let mut iter = fragments.into_iter();
        let Some(first) = iter.next() else {
            return Self::trusted("FALSE");
        };

        let mut fragment = first.wrapped();
        for next in iter {
            fragment.push_sql(separator);
            fragment.push_fragment(next.wrapped());
        }
        fragment
    }

    #[must_use]
    fn function(name: &str, fragments: Vec<Self>) -> Self {
        let mut fragment = Self::trusted(name);
        fragment.push_sql("(");

        let mut iter = fragments.into_iter();
        if let Some(first) = iter.next() {
            fragment.push_fragment(first);
            for next in iter {
                fragment.push_sql(", ");
                fragment.push_fragment(next);
            }
        }

        fragment.push_sql(")");
        fragment
    }
}

/// Maps a residual fact to a trusted Postgres predicate over the candidate row.
pub trait PgFactPredicates {
    /// Returns a predicate for the given fact, or `None` when the fact cannot be
    /// represented by this backend.
    fn predicate(&self, fact: &FactId, cx: &Context) -> Option<PgFragment>;
}

/// Maps a policy outcome to a total-order SQL ordinal.
pub trait SqlOutcome {
    /// Returns the scalar ordinal used by SQL `LEAST` and `GREATEST`.
    fn to_sql_ordinal(&self) -> i64;
}

impl SqlOutcome for () {
    fn to_sql_ordinal(&self) -> i64 {
        0
    }
}

/// Projection strategy for turning outcomes into SQL fragments.
pub trait OutcomeProjection<O> {
    /// Builds a SQL fragment for a constant outcome.
    fn constant(&self, outcome: &O) -> Result<PgFragment, LowerError>;
}

/// Outcome projection backed by [`SqlOutcome`].
#[derive(Clone, Copy, Debug, Default)]
pub struct OrdinalProjection;

impl<O: SqlOutcome> OutcomeProjection<O> for OrdinalProjection {
    fn constant(&self, outcome: &O) -> Result<PgFragment, LowerError> {
        Ok(PgFragment::bind_i64(outcome.to_sql_ordinal()))
    }
}

/// Projection that rejects grade lowering.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoGradeProjection;

impl<O> OutcomeProjection<O> for NoGradeProjection {
    fn constant(&self, _outcome: &O) -> Result<PgFragment, LowerError> {
        Err(LowerError::NonTotalGrade)
    }
}

/// Postgres lowerer for gatekeep residual policies.
#[derive(Clone, Debug)]
pub struct PgLowerer<P, M = OrdinalProjection> {
    predicates: P,
    projection: M,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PgLowered {
    filter: PgFragment,
    grade: PgFragment,
}

impl<P> PgLowerer<P, OrdinalProjection> {
    /// Builds a lowerer using ordinal grade projection.
    #[must_use]
    pub const fn new(predicates: P) -> Self {
        Self::with_projection(predicates, OrdinalProjection)
    }
}

impl<P, M> PgLowerer<P, M> {
    /// Builds a lowerer using a caller-supplied projection strategy.
    #[must_use]
    pub const fn with_projection(predicates: P, projection: M) -> Self {
        Self {
            predicates,
            projection,
        }
    }

    /// Lowers only the Boolean filter. This works for every outcome lattice.
    pub fn lower_filter<O>(
        &self,
        residual: &ResidualPolicy<O>,
        cx: &Context,
    ) -> Result<PgFragment, LowerError>
    where
        P: PgFactPredicates,
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
        node: ResidualPolicyNode<'_, O, PgFragment>,
        cx: &Context,
    ) -> Result<PgFragment, LowerError>
    where
        P: PgFactPredicates,
    {
        match node {
            ResidualPolicyNode::Permit(_) | ResidualPolicyNode::PermitWithTrace { .. } => {
                Ok(PgFragment::trusted("TRUE"))
            }
            ResidualPolicyNode::Deny | ResidualPolicyNode::DenyWithTrace { .. } => {
                Ok(PgFragment::trusted("FALSE"))
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
                        Some(fallback) => PgFragment::binary(" OR ", vec![primary, fallback]),
                        None => primary,
                    })
                }
            }
        }
    }

    fn lower_condition(&self, condition: &Condition, cx: &Context) -> Result<PgFragment, LowerError>
    where
        P: PgFactPredicates,
    {
        match condition {
            Condition::Always => Ok(PgFragment::trusted("TRUE")),
            Condition::Never => Ok(PgFragment::trusted("FALSE")),
            Condition::Has(fact) => self
                .predicates
                .predicate(fact, cx)
                .map(is_true)
                .ok_or_else(|| LowerError::Unlowerable(fact.clone())),
            Condition::Not(inner) => {
                Ok(PgFragment::unary("NOT ", self.lower_condition(inner, cx)?))
            }
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
    ) -> Result<PgLowered, LowerError>
    where
        P: PgFactPredicates,
        M: OutcomeProjection<O>,
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
        node: ResidualPolicyNode<'_, O, PgLowered>,
        cx: &Context,
    ) -> Result<PgLowered, LowerError>
    where
        P: PgFactPredicates,
        M: OutcomeProjection<O>,
    {
        match node {
            ResidualPolicyNode::Permit(outcome)
            | ResidualPolicyNode::PermitWithTrace { outcome, .. } => Ok(PgLowered {
                filter: PgFragment::trusted("TRUE"),
                grade: self.projection.constant(outcome)?,
            }),
            ResidualPolicyNode::Deny | ResidualPolicyNode::DenyWithTrace { .. } => Ok(PgLowered {
                filter: PgFragment::trusted("FALSE"),
                grade: PgFragment::trusted("NULL"),
            }),
            ResidualPolicyNode::Grant {
                outcome, condition, ..
            } => {
                let filter = self.lower_condition(condition, cx)?;
                let outcome = self.projection.constant(outcome)?;
                Ok(PgLowered {
                    filter: filter.clone(),
                    grade: case_when(filter, outcome, PgFragment::trusted("NULL")),
                })
            }
            ResidualPolicyNode::All { arms, .. } => {
                let (filters, grades) = unzip_lowered(arms);
                Ok(PgLowered {
                    filter: fragment_set(filters, " AND ", "FALSE"),
                    grade: grade_set(grades, "LEAST"),
                })
            }
            ResidualPolicyNode::Any { arms, .. } => {
                let (filters, grades) = unzip_lowered(arms);
                Ok(PgLowered {
                    filter: fragment_set(filters, " OR ", "FALSE"),
                    grade: grade_set(grades, "GREATEST"),
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
                    Some(fallback) => PgLowered {
                        filter: PgFragment::binary(
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

impl<O, P, M> QueryLowering<O> for PgLowerer<P, M>
where
    P: PgFactPredicates,
    M: OutcomeProjection<O>,
{
    type Filter = PgFragment;
    type Projection = PgFragment;

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

fn lower_condition_set(
    conditions: &[Condition],
    separator: &str,
    empty: &str,
    lower: impl FnMut(&Condition) -> Result<PgFragment, LowerError>,
) -> Result<PgFragment, LowerError> {
    if conditions.is_empty() {
        return Ok(PgFragment::trusted(empty));
    }
    let fragments = conditions
        .iter()
        .map(lower)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PgFragment::binary(separator, fragments))
}

fn fragment_set(fragments: Vec<PgFragment>, separator: &str, empty: &str) -> PgFragment {
    if fragments.is_empty() {
        PgFragment::trusted(empty)
    } else {
        PgFragment::binary(separator, fragments)
    }
}

fn grade_set(grades: Vec<PgFragment>, function: &str) -> PgFragment {
    if grades.is_empty() {
        PgFragment::trusted("NULL")
    } else {
        PgFragment::function(function, grades)
    }
}

fn unzip_lowered(lowered: Vec<PgLowered>) -> (Vec<PgFragment>, Vec<PgFragment>) {
    lowered
        .into_iter()
        .map(|lowered| (lowered.filter, lowered.grade))
        .unzip()
}

fn case_when(condition: PgFragment, then_expr: PgFragment, else_expr: PgFragment) -> PgFragment {
    let mut fragment = PgFragment::trusted("CASE WHEN ");
    fragment.push_fragment(condition);
    fragment.push_sql(" THEN ");
    fragment.push_fragment(then_expr);
    fragment.push_sql(" ELSE ");
    fragment.push_fragment(else_expr);
    fragment.push_sql(" END");
    fragment
}

fn is_true(predicate: PgFragment) -> PgFragment {
    let mut fragment = PgFragment::trusted("(");
    fragment.push_fragment(predicate);
    fragment.push_sql(") IS TRUE");
    fragment
}

fn push_bind(builder: &mut QueryBuilder<Postgres>, value: &PgValue) {
    match value {
        PgValue::Bool(value) => {
            builder.push_bind(*value);
        }
        PgValue::I64(value) => {
            builder.push_bind(*value);
        }
        PgValue::Text(value) => {
            builder.push_bind(value.clone());
        }
    }
}
