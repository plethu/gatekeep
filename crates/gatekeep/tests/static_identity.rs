//! Static tenant identities enforce the same forbidden scalars as owned values.
use std::panic::catch_unwind;

use gatekeep::{FactId, StaticFactId, StaticTenantId, TenantId};

#[test]
fn static_tenant_rejects_controls_and_noncharacters() {
    for value in [
        "a\u{0080}",
        "a\u{0085}",
        "a\u{009f}",
        "a\u{fdd0}",
        "a\u{ffff}",
        "a\u{1fffe}",
        "a\u{10ffff}",
    ] {
        assert!(TenantId::new(value).is_err());
        assert!(catch_unwind(|| StaticTenantId::new(value)).is_err());
    }
}

#[test]
fn static_tenant_preserves_valid_multibyte_identities() -> Result<(), gatekeep::GatekeepError> {
    const ID: StaticTenantId = StaticTenantId::new("é-日本-🦀");
    assert_eq!(ID.to_owned_id()?, TenantId::new("é-日本-🦀")?);
    Ok(())
}

#[test]
fn static_identifiers_reject_unicode_only_whitespace() {
    for value in [
        "\u{0009}",
        "\u{000a}",
        "\u{000b}",
        "\u{000c}",
        "\u{000d}",
        " ",
        "\u{0085}",
        "\u{00a0}",
        "\u{1680}",
        "\u{2000}",
        "\u{2001}",
        "\u{2002}",
        "\u{2003}",
        "\u{2004}",
        "\u{2005}",
        "\u{2006}",
        "\u{2007}",
        "\u{2008}",
        "\u{2009}",
        "\u{200a}",
        "\u{2028}",
        "\u{2029}",
        "\u{202f}",
        "\u{205f}",
        "\u{3000}",
        " \u{00a0}\u{3000}",
    ] {
        assert!(FactId::new(value).is_err());
        assert!(catch_unwind(|| StaticFactId::new(value)).is_err());
    }
}

#[test]
fn static_identity_preserves_authored_surrounding_whitespace() -> Result<(), gatekeep::GatekeepError>
{
    const ID: StaticFactId = StaticFactId::new("\u{3000}reader\u{00a0}");
    assert_eq!(ID.to_owned_id()?, FactId::new("\u{3000}reader\u{00a0}")?);
    Ok(())
}
