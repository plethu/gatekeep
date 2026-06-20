use sqlx::{
    Postgres, QueryBuilder,
    types::{
        Uuid,
        time::{Date, OffsetDateTime, PrimitiveDateTime, Time},
    },
};

/// Postgres scalar value carried by a lowered SQL fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PgValue {
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

macro_rules! impl_pg_value_from {
    ($ty:ty, $variant:ident) => {
        impl From<$ty> for PgValue {
            fn from(value: $ty) -> Self {
                Self::$variant(value)
            }
        }
    };
}

impl_pg_value_from!(bool, Bool);
impl_pg_value_from!(i16, I16);
impl_pg_value_from!(i32, I32);
impl_pg_value_from!(i64, I64);
impl_pg_value_from!(String, Text);
impl_pg_value_from!(Vec<u8>, Bytes);
impl_pg_value_from!(Uuid, Uuid);
impl_pg_value_from!(Date, Date);
impl_pg_value_from!(Time, Time);
impl_pg_value_from!(PrimitiveDateTime, Timestamp);
impl_pg_value_from!(OffsetDateTime, TimestampTz);

impl From<&str> for PgValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<&[u8]> for PgValue {
    fn from(value: &[u8]) -> Self {
        Self::Bytes(value.to_vec())
    }
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
    /// bind fragments built with [`Self::bind`].
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

    /// Builds a bind fragment from a supported Postgres scalar value.
    #[must_use]
    pub fn bind(value: impl Into<PgValue>) -> Self {
        Self {
            parts: vec![SqlPart::Bind(value.into())],
        }
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
    pub(crate) fn binary(separator: &str, fragments: Vec<Self>) -> Self {
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
    pub(crate) fn function(name: &str, fragments: Vec<Self>) -> Self {
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

fn push_bind(builder: &mut QueryBuilder<Postgres>, value: &PgValue) {
    match value {
        PgValue::Bool(value) => {
            builder.push_bind(*value);
        }
        PgValue::I16(value) => {
            builder.push_bind(*value);
        }
        PgValue::I32(value) => {
            builder.push_bind(*value);
        }
        PgValue::I64(value) => {
            builder.push_bind(*value);
        }
        PgValue::Text(value) => {
            builder.push_bind(value.clone());
        }
        PgValue::Bytes(value) => {
            builder.push_bind(value.clone());
        }
        PgValue::Uuid(value) => {
            builder.push_bind(*value);
        }
        PgValue::Date(value) => {
            builder.push_bind(*value);
        }
        PgValue::Time(value) => {
            builder.push_bind(*value);
        }
        PgValue::Timestamp(value) => {
            builder.push_bind(*value);
        }
        PgValue::TimestampTz(value) => {
            builder.push_bind(*value);
        }
    }
}
