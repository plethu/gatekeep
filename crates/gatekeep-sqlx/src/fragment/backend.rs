use super::{SqlxDriver, SqlxValue};
use sqlx::QueryBuilder;
use std::fmt::Debug;

/// `SQLx` backend supported by gatekeep lowering.
pub trait GatekeepSqlxBackend: Clone + Copy + Debug + Send + Sync + 'static {
    /// `SQLx` database driver for this backend.
    type Database: sqlx::Database;

    /// Database driver represented by this backend.
    const DRIVER: SqlxDriver;

    /// Stable backend name.
    const NAME: &'static str;

    /// Appends one bind placeholder to rendered SQL.
    fn push_placeholder(sql: &mut String, index: usize);

    /// Appends one typed bind value to a `SQLx` query builder.
    fn push_bind(builder: &mut QueryBuilder<Self::Database>, value: &SqlxValue);

    /// Name of the SQL function that returns the lower of two non-null grades.
    const MIN_FUNCTION: &'static str;

    /// Name of the SQL function that returns the higher of two non-null grades.
    const MAX_FUNCTION: &'static str;

    /// Whether the backend's grade functions return `NULL` when any input is
    /// `NULL`.
    const GRADE_FUNCTION_PROPAGATES_NULL: bool;
}

macro_rules! push_sqlx_bind {
    ($builder:expr, $value:expr) => {
        match $value {
            SqlxValue::Bool(value) => {
                $builder.push_bind(*value);
            }
            SqlxValue::I16(value) => {
                $builder.push_bind(*value);
            }
            SqlxValue::I32(value) => {
                $builder.push_bind(*value);
            }
            SqlxValue::I64(value) => {
                $builder.push_bind(*value);
            }
            SqlxValue::Text(value) => {
                $builder.push_bind(value.clone());
            }
            SqlxValue::Bytes(value) => {
                $builder.push_bind(value.clone());
            }
            SqlxValue::Uuid(value) => {
                $builder.push_bind(*value);
            }
            SqlxValue::Date(value) => {
                $builder.push_bind(*value);
            }
            SqlxValue::Time(value) => {
                $builder.push_bind(*value);
            }
            SqlxValue::Timestamp(value) => {
                $builder.push_bind(*value);
            }
            SqlxValue::TimestampTz(value) => {
                $builder.push_bind(*value);
            }
        }
    };
}

/// Postgres backend marker.
#[cfg(feature = "postgres")]
#[derive(Clone, Copy, Debug)]
pub struct PostgresBackend;

#[cfg(feature = "postgres")]
impl GatekeepSqlxBackend for PostgresBackend {
    type Database = sqlx::Postgres;

    const DRIVER: SqlxDriver = SqlxDriver::Postgres;
    const NAME: &'static str = "postgres";
    const MIN_FUNCTION: &'static str = "LEAST";
    const MAX_FUNCTION: &'static str = "GREATEST";
    const GRADE_FUNCTION_PROPAGATES_NULL: bool = false;

    fn push_placeholder(sql: &mut String, index: usize) {
        sql.push('$');
        sql.push_str(&index.to_string());
    }

    fn push_bind(builder: &mut QueryBuilder<Self::Database>, value: &SqlxValue) {
        push_sqlx_bind!(builder, value);
    }
}

/// `SQLite` backend marker.
#[cfg(feature = "sqlite")]
#[derive(Clone, Copy, Debug)]
pub struct SqliteBackend;

#[cfg(feature = "sqlite")]
impl GatekeepSqlxBackend for SqliteBackend {
    type Database = sqlx::Sqlite;

    const DRIVER: SqlxDriver = SqlxDriver::Sqlite;
    const NAME: &'static str = "sqlite";
    const MIN_FUNCTION: &'static str = "min";
    const MAX_FUNCTION: &'static str = "max";
    const GRADE_FUNCTION_PROPAGATES_NULL: bool = true;

    fn push_placeholder(sql: &mut String, _index: usize) {
        sql.push('?');
    }

    fn push_bind(builder: &mut QueryBuilder<Self::Database>, value: &SqlxValue) {
        push_sqlx_bind!(builder, value);
    }
}

/// `MySQL` backend marker.
#[cfg(feature = "mysql")]
#[derive(Clone, Copy, Debug)]
pub struct MySqlBackend;

#[cfg(feature = "mysql")]
impl GatekeepSqlxBackend for MySqlBackend {
    type Database = sqlx::MySql;

    const DRIVER: SqlxDriver = SqlxDriver::MySql;
    const NAME: &'static str = "mysql";
    const MIN_FUNCTION: &'static str = "LEAST";
    const MAX_FUNCTION: &'static str = "GREATEST";
    const GRADE_FUNCTION_PROPAGATES_NULL: bool = true;

    fn push_placeholder(sql: &mut String, _index: usize) {
        sql.push('?');
    }

    fn push_bind(builder: &mut QueryBuilder<Self::Database>, value: &SqlxValue) {
        push_sqlx_bind!(builder, value);
    }
}
