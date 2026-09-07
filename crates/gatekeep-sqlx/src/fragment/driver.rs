use url::Url;

use super::GatekeepSqlxBackend;

/// Supported `SQLx` database driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SqlxDriver {
    /// Postgres `SQLx` driver.
    Postgres,
    /// `SQLite` `SQLx` driver.
    Sqlite,
    /// `MySQL` `SQLx` driver.
    MySql,
}

impl SqlxDriver {
    /// Stable driver name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Sqlite => "sqlite",
            Self::MySql => "mysql",
        }
    }

    /// Whether this crate was compiled with the matching backend feature.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        match self {
            Self::Postgres => cfg!(feature = "postgres"),
            Self::Sqlite => cfg!(feature = "sqlite"),
            Self::MySql => cfg!(feature = "mysql"),
        }
    }
}

/// Database driver configuration error.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SqlxDriverError {
    /// The URL scheme is not recognized as a `SQLx` database driver.
    #[error("unsupported SQLx database URL scheme {scheme:?}")]
    UnsupportedUrlScheme {
        /// Validated scheme from an explicit `scheme://` URL; absent for
        /// ambiguous prefixes that could contain private credentials.
        scheme: Option<String>,
    },

    /// The URL selects a driver whose feature was not enabled.
    #[error("SQLx driver {driver} is not enabled for gatekeep-sqlx")]
    DriverNotEnabled {
        /// Driver inferred from the URL.
        driver: &'static str,
    },

    /// The configured driver does not match the selected backend.
    #[error("SQLx backend mismatch: expected {expected}, found {actual}")]
    BackendMismatch {
        /// Backend expected by the selected lowerer.
        expected: &'static str,
        /// Driver inferred from runtime configuration.
        actual: &'static str,
    },
}

/// Infers the `SQLx` driver from a database URL or `SQLx`-style `SQLite` memory URL.
///
/// # Errors
///
/// Returns [`SqlxDriverError`] when the URL scheme is unsupported or when the
/// inferred driver was not enabled at compile time.
pub fn infer_enabled_driver_from_url(database_url: &str) -> Result<SqlxDriver, SqlxDriverError> {
    let driver = infer_driver_from_url(database_url)?;
    if driver.is_enabled() {
        Ok(driver)
    } else {
        Err(SqlxDriverError::DriverNotEnabled {
            driver: driver.name(),
        })
    }
}

/// Validates that a database URL matches a selected backend.
///
/// # Errors
///
/// Returns [`SqlxDriverError`] when the URL is unsupported, names a disabled
/// driver, or names a different driver from `B`.
pub fn validate_database_url_for_backend<B>(database_url: &str) -> Result<(), SqlxDriverError>
where
    B: GatekeepSqlxBackend,
{
    let actual = infer_enabled_driver_from_url(database_url)?;
    if actual == B::DRIVER {
        Ok(())
    } else {
        Err(SqlxDriverError::BackendMismatch {
            expected: B::NAME,
            actual: actual.name(),
        })
    }
}

fn infer_driver_from_url(database_url: &str) -> Result<SqlxDriver, SqlxDriverError> {
    if database_url.starts_with("sqlite:") {
        return Ok(SqlxDriver::Sqlite);
    }

    let Some((scheme, rest)) = database_url.split_once(':') else {
        return Err(SqlxDriverError::UnsupportedUrlScheme { scheme: None });
    };

    match scheme {
        "postgres" | "postgresql" => Ok(SqlxDriver::Postgres),
        "mysql" | "mariadb" => Ok(SqlxDriver::MySql),
        "sqlite" => Ok(SqlxDriver::Sqlite),
        _ => Err(SqlxDriverError::UnsupportedUrlScheme {
            scheme: Url::parse(database_url)
                .ok()
                .filter(|url| rest.starts_with("//") && url.scheme().eq_ignore_ascii_case(scheme))
                .map(|_| scheme.to_owned()),
        }),
    }
}
