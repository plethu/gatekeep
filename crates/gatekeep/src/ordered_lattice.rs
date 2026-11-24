//! Declarative `Lattice` implementations for ordered outcome tiers.

/// Implements [`Lattice`](crate::Lattice) for a field-less enum from a listed
/// order, narrowest first.
///
/// `meet` returns the narrower of two values, `join` the broader, `bottom` the
/// first listed variant and `top` the last. The listed order is the only order
/// used: the enum does not need to derive `Ord`, and a derived `Ord` does not
/// change the result.
///
/// Every variant must be listed. A missing variant is a compile error, and a
/// repeated variant triggers the `unreachable_patterns` lint. The enum still
/// needs `Clone`, `Eq` and `Debug`, which `Lattice` requires.
///
/// ```
/// #[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// enum Access {
///     None,
///     Read,
///     Edit,
///     Full,
/// }
///
/// gatekeep::ordered_lattice!(Access: None < Read < Edit < Full);
///
/// use gatekeep::Lattice;
/// assert_eq!(Access::Edit.meet(&Access::Read), Access::Read);
/// assert_eq!(Access::Edit.join(&Access::Read), Access::Edit);
/// assert_eq!(Access::top(), Access::Full);
/// assert_eq!(Access::bottom(), Access::None);
/// ```
///
/// Omitting a variant does not compile:
///
/// ```compile_fail
/// #[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// enum Access { None, Read, Full }
///
/// gatekeep::ordered_lattice!(Access: None < Full);
/// ```
///
/// Use a hand-written `Lattice` for sets, scopes and other outcomes that are
/// not a single chain.
#[macro_export]
macro_rules! ordered_lattice {
    ($ty:ty : $bottom:ident $(< $rest:ident)+ $(,)?) => {
        impl $crate::Lattice for $ty {
            fn meet(&self, other: &Self) -> Self {
                // Exhaustiveness check: every variant must appear in the order.
                match self {
                    Self::$bottom $(| Self::$rest)+ => {}
                }
                [Self::$bottom $(, Self::$rest)+]
                    .into_iter()
                    .find(|candidate| candidate == self || candidate == other)
                    .unwrap_or_else(|| self.clone())
            }

            fn join(&self, other: &Self) -> Self {
                [Self::$bottom $(, Self::$rest)+]
                    .into_iter()
                    .rev()
                    .find(|candidate| candidate == self || candidate == other)
                    .unwrap_or_else(|| self.clone())
            }

            fn top() -> Self {
                let [.., top] = [Self::$bottom $(, Self::$rest)+];
                top
            }

            fn bottom() -> Self {
                Self::$bottom
            }
        }
    };
}
