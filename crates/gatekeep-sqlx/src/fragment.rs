use std::marker::PhantomData;

use sqlx::{
    QueryBuilder,
    types::{
        Uuid,
        time::{Date, OffsetDateTime, PrimitiveDateTime, Time},
    },
};

mod backend;
mod driver;
mod tenant;
pub use backend::GatekeepSqlxBackend;
#[cfg(feature = "mysql")]
pub use backend::MySqlBackend;
#[cfg(feature = "postgres")]
pub use backend::PostgresBackend;
#[cfg(feature = "sqlite")]
pub use backend::SqliteBackend;
pub use driver::{
    SqlxDriver, SqlxDriverError, infer_enabled_driver_from_url, validate_database_url_for_backend,
};
pub use tenant::{
    MAX_TENANT_IDENTIFIER_BYTES, TenantColumn, TenantColumnError, TenantIdentifierPart,
};

/// Scalar value carried by a lowered SQL fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SqlxValue {
    /// Boolean bind value.
    Bool(bool),
    /// Signed 16-bit integer bind value.
    I16(i16),
    /// Signed 32-bit integer bind value.
    I32(i32),
    /// Signed 64-bit integer bind value.
    I64(i64),
    /// Text bind value.
    Text(String),
    /// Binary bind value.
    Bytes(Vec<u8>),
    /// UUID bind value.
    Uuid(Uuid),
    /// Date bind value.
    Date(Date),
    /// Time bind value.
    Time(Time),
    /// Timestamp without time zone bind value.
    Timestamp(PrimitiveDateTime),
    /// Timestamp with time zone bind value.
    TimestampTz(OffsetDateTime),
}

macro_rules! impl_sqlx_value_from {
    ($ty:ty, $variant:ident) => {
        impl From<$ty> for SqlxValue {
            fn from(value: $ty) -> Self {
                Self::$variant(value)
            }
        }
    };
}

impl_sqlx_value_from!(bool, Bool);
impl_sqlx_value_from!(i16, I16);
impl_sqlx_value_from!(i32, I32);
impl_sqlx_value_from!(i64, I64);
impl_sqlx_value_from!(String, Text);
impl_sqlx_value_from!(Vec<u8>, Bytes);
impl_sqlx_value_from!(Uuid, Uuid);
impl_sqlx_value_from!(Date, Date);
impl_sqlx_value_from!(Time, Time);
impl_sqlx_value_from!(PrimitiveDateTime, Timestamp);
impl_sqlx_value_from!(OffsetDateTime, TimestampTz);

impl From<&str> for SqlxValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<&[u8]> for SqlxValue {
    fn from(value: &[u8]) -> Self {
        Self::Bytes(value.to_vec())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SqlPart {
    Text(String),
    Bind(SqlxValue),
}

/// Trusted SQL plus ordered bind values for one `SQLx` backend.
#[derive(Debug, PartialEq, Eq)]
pub struct SqlxFragment<B> {
    parts: Vec<SqlPart>,
    backend: PhantomData<fn() -> B>,
}

impl<B> Clone for SqlxFragment<B> {
    fn clone(&self) -> Self {
        Self {
            parts: self.parts.clone(),
            backend: PhantomData,
        }
    }
}

impl<B> Default for SqlxFragment<B> {
    fn default() -> Self {
        Self {
            parts: Vec::new(),
            backend: PhantomData,
        }
    }
}

impl<B> SqlxFragment<B> {
    /// Builds a fragment from SQL owned by the application.
    ///
    /// Callers must not pass user-supplied text here. Dynamic values belong in
    /// bind fragments built with [`Self::bind`].
    #[must_use]
    pub fn trusted(sql: impl Into<String>) -> Self {
        let sql = sql.into();
        if sql.is_empty() {
            Self::default()
        } else {
            Self {
                parts: vec![SqlPart::Text(sql)],
                backend: PhantomData,
            }
        }
    }

    /// Builds a bind fragment from a supported `SQLx` scalar value.
    #[must_use]
    pub fn bind(value: impl Into<SqlxValue>) -> Self {
        Self {
            parts: vec![SqlPart::Bind(value.into())],
            backend: PhantomData,
        }
    }

    /// Returns the ordered bind values.
    pub fn binds(&self) -> impl Iterator<Item = &SqlxValue> {
        self.parts.iter().filter_map(|part| match part {
            SqlPart::Text(_) => None,
            SqlPart::Bind(value) => Some(value),
        })
    }

    /// Appends another fragment to this one.
    pub fn push_fragment(&mut self, fragment: Self) {
        self.parts.extend(fragment.parts);
    }

    pub(crate) fn push_sql(&mut self, sql: impl Into<String>) {
        let sql = sql.into();
        if !sql.is_empty() {
            self.parts.push(SqlPart::Text(sql));
        }
    }

    #[must_use]
    pub(crate) fn wrapped(self) -> Self {
        let mut fragment = Self::trusted("(");
        fragment.push_fragment(self);
        fragment.push_sql(")");
        fragment
    }

    #[must_use]
    pub(crate) fn unary(prefix: &str, inner: Self) -> Self {
        let mut fragment = Self::trusted(prefix);
        fragment.push_fragment(inner.wrapped());
        fragment
    }

    #[must_use]
    pub(crate) fn binary(separator: &str, fragments: impl IntoIterator<Item = Self>) -> Self {
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
    pub(crate) fn function(name: &str, fragments: impl IntoIterator<Item = Self>) -> Self {
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

impl<B> SqlxFragment<B>
where
    B: GatekeepSqlxBackend,
{
    /// Converts the fragment to SQL with this backend's placeholder syntax.
    #[must_use]
    pub fn to_sql(&self) -> String {
        let mut sql = String::new();
        let mut placeholders = 0usize;

        for part in &self.parts {
            match part {
                SqlPart::Text(text) => sql.push_str(text),
                SqlPart::Bind(_) => {
                    // Each bind occupies a Vec entry, so the count cannot exceed usize::MAX.
                    placeholders = placeholders.saturating_add(1);
                    B::push_placeholder(&mut sql, placeholders);
                }
            }
        }
        sql
    }

    /// Appends this fragment to a `SQLx` query builder.
    pub fn push_to(&self, builder: &mut QueryBuilder<B::Database>) {
        for part in &self.parts {
            match part {
                SqlPart::Text(text) => {
                    builder.push(text);
                }
                SqlPart::Bind(value) => B::push_bind(builder, value),
            }
        }
    }
}

/// Postgres scalar value carried by a lowered SQL fragment.
#[cfg(feature = "postgres")]
pub type PgValue = SqlxValue;

/// Trusted Postgres SQL plus ordered bind values.
#[cfg(feature = "postgres")]
pub type PgFragment = SqlxFragment<PostgresBackend>;

#[cfg(feature = "postgres")]
impl SqlxFragment<PostgresBackend> {
    /// Converts the fragment to Postgres placeholders (`$1`, `$2`, ...).
    #[must_use]
    pub fn to_postgres_sql(&self) -> String {
        self.to_sql()
    }
}
