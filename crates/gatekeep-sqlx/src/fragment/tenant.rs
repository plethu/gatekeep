/// Maximum portable SQL identifier length accepted by this adapter.
pub const MAX_TENANT_IDENTIFIER_BYTES: usize = 63;

/// Which component of a qualified tenant column failed validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TenantIdentifierPart {
    /// The table identifier.
    Table,
    /// The column identifier.
    Column,
}

/// Failure while constructing a tenant column identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TenantColumnError {
    /// The identifier was empty or exceeded the portable bound.
    #[error("tenant {part:?} identifier must be 1..={max} ASCII bytes")]
    InvalidLength {
        /// Identifier component that failed validation.
        part: TenantIdentifierPart,
        /// Maximum accepted byte length.
        max: usize,
    },
    /// The identifier was not an unquoted SQL identifier.
    #[error("tenant {part:?} identifier {value:?} is not a safe unquoted SQL identifier")]
    InvalidCharacters {
        /// Identifier component that failed validation.
        part: TenantIdentifierPart,
        /// Rejected static identifier.
        value: &'static str,
    },
}

/// Validated application-owned table and column names for tenant filtering.
///
/// Both components use the portable unquoted SQL identifier grammar
/// `[A-Za-z_][A-Za-z0-9_]*`. SQL operators, literals, comments, quoting, and
/// qualified expressions therefore cannot enter the generated predicate.
/// Tenant values remain typed `SQLx` binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TenantColumn {
    table: &'static str,
    column: &'static str,
}

impl TenantColumn {
    /// Creates a validated qualified tenant column.
    ///
    /// # Errors
    ///
    /// Returns [`TenantColumnError`] for empty, overlong, or non-identifier
    /// table/column components.
    pub const fn new(table: &'static str, column: &'static str) -> Result<Self, TenantColumnError> {
        match validate_tenant_identifier(table, TenantIdentifierPart::Table) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }

        match validate_tenant_identifier(column, TenantIdentifierPart::Column) {
            Ok(()) => {}
            Err(error) => return Err(error),
        }
        Ok(Self { table, column })
    }

    /// Returns the validated table identifier.
    #[must_use]
    pub const fn table(self) -> &'static str {
        self.table
    }

    /// Returns the validated column identifier.
    #[must_use]
    pub const fn column(self) -> &'static str {
        self.column
    }

    /// Renders the qualified identifier from already validated components.
    #[must_use]
    pub fn qualified(self) -> String {
        format!("{}.{}", self.table, self.column)
    }
}

const fn validate_tenant_identifier(
    value: &'static str,
    part: TenantIdentifierPart,
) -> Result<(), TenantColumnError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_TENANT_IDENTIFIER_BYTES {
        return Err(TenantColumnError::InvalidLength {
            part,
            max: MAX_TENANT_IDENTIFIER_BYTES,
        });
    }

    let Some((first, mut remaining)) = bytes.split_first() else {
        return Err(TenantColumnError::InvalidLength {
            part,
            max: MAX_TENANT_IDENTIFIER_BYTES,
        });
    };

    if !(first.is_ascii_alphabetic() || *first == b'_') {
        return Err(TenantColumnError::InvalidCharacters { part, value });
    }

    while let [byte, rest @ ..] = remaining {
        if !(byte.is_ascii_alphanumeric() || *byte == b'_') {
            return Err(TenantColumnError::InvalidCharacters { part, value });
        }
        remaining = rest;
    }

    if is_reserved_tenant_identifier(value) {
        return Err(TenantColumnError::InvalidCharacters { part, value });
    }

    Ok(())
}

const fn is_reserved_tenant_identifier(value: &str) -> bool {
    matches_ascii_case_insensitive(
        value,
        &[
            "all", "and", "as", "between", "by", "case", "else", "end", "exists", "false", "from",
            "group", "having", "in", "is", "join", "like", "limit", "not", "null", "offset", "on",
            "or", "order", "select", "then", "true", "union", "when", "where",
        ],
    )
}

const fn matches_ascii_case_insensitive(value: &str, mut candidates: &[&str]) -> bool {
    while let [candidate, rest @ ..] = candidates {
        if value.eq_ignore_ascii_case(candidate) {
            return true;
        }
        candidates = rest;
    }
    false
}
