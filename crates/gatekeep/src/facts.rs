use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

use crate::{Fact, FactId, GatekeepError, GatekeepResult};

/// Opaque serialized value used only for trace and audit output.
pub type TraceValue = serde_json::Value;

/// Presence state of a named fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Presence {
    /// Fact is present.
    Present,
    /// Fact is absent.
    Absent,
    /// Fact is intentionally deferred to query lowering.
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Facts(BTreeMap<FactId, (Presence, Option<TraceValue>)>);

impl Facts {
    fn from_entries(entries: impl IntoIterator<Item = (FactId, Presence)>) -> Self {
        let mut facts = Self::default();
        for (fact, presence) in entries {
            facts.insert(fact, presence, None);
        }
        facts
    }

    fn try_from_known_entries(
        entries: impl IntoIterator<Item = (FactId, Presence)>,
    ) -> GatekeepResult<Self> {
        let mut facts = Self::default();
        for (fact, presence) in entries {
            facts.try_insert_known(fact, presence)?;
        }
        Ok(facts)
    }

    fn insert(&mut self, fact: FactId, presence: Presence, value: Option<TraceValue>) {
        self.0.insert(fact, (presence, value));
    }

    fn insert_typed<F: Fact>(&mut self, presence: Presence) {
        self.insert(FactId::from_trusted(F::ID.as_str()), presence, None);
    }

    fn try_insert_known(&mut self, fact: FactId, presence: Presence) -> GatekeepResult<()> {
        if presence == Presence::Unknown {
            return Err(GatekeepError::InvalidPolicyRecord {
                reason: "known facts cannot contain unknown presence",
            });
        }
        self.insert(fact, presence, None);
        Ok(())
    }

    fn presence(&self, fact: &FactId) -> Presence {
        self.0
            .get(fact)
            .map_or(Presence::Absent, |(presence, _value)| *presence)
    }

    fn iter(&self) -> impl Iterator<Item = (&FactId, Presence)> {
        self.0
            .iter()
            .map(|(fact, (presence, _value))| (fact, *presence))
    }
}

/// Fact bundle accepted by full evaluation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct KnownFacts(Facts);

impl KnownFacts {
    /// Creates an empty fact bundle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds known facts from explicit entries, rejecting `Presence::Unknown`.
    pub fn from_entries(
        entries: impl IntoIterator<Item = (FactId, Presence)>,
    ) -> GatekeepResult<Self> {
        Facts::try_from_known_entries(entries).map(Self)
    }

    pub(crate) fn from_known_entries(
        entries: impl IntoIterator<Item = (FactId, Presence)>,
    ) -> Self {
        Self(Facts::from_entries(
            entries
                .into_iter()
                .filter(|(_fact, presence)| *presence != Presence::Unknown),
        ))
    }

    /// Marks a typed fact as present.
    #[must_use]
    pub fn with_present<F: Fact>(mut self) -> Self {
        self.0.insert_typed::<F>(Presence::Present);
        self
    }

    /// Marks a typed fact as absent.
    #[must_use]
    pub fn with_absent<F: Fact>(mut self) -> Self {
        self.0.insert_typed::<F>(Presence::Absent);
        self
    }

    /// Adds a runtime fact, rejecting `Presence::Unknown`.
    pub fn try_with_fact(mut self, fact: FactId, presence: Presence) -> GatekeepResult<Self> {
        self.0.try_insert_known(fact, presence)?;
        Ok(self)
    }

    /// Returns a fact's presence, defaulting to absent when omitted.
    #[must_use]
    pub fn presence(&self, fact: &FactId) -> Presence {
        self.0.presence(fact)
    }
}

impl<'de> Deserialize<'de> for KnownFacts {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let facts = Facts::deserialize(deserializer)?;
        for (_fact, presence) in facts.iter() {
            if presence == Presence::Unknown {
                return Err(serde::de::Error::custom(
                    "known facts cannot contain unknown presence",
                ));
            }
        }
        Ok(Self(facts))
    }
}

/// Fact bundle accepted by partial evaluation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialFacts(Facts);

impl PartialFacts {
    /// Creates an empty partial fact bundle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds partial facts from explicit entries.
    pub fn from_entries(entries: impl IntoIterator<Item = (FactId, Presence)>) -> Self {
        Self(Facts::from_entries(entries))
    }

    /// Marks a typed fact as present.
    #[must_use]
    pub fn with_present<F: Fact>(mut self) -> Self {
        self.0.insert_typed::<F>(Presence::Present);
        self
    }

    /// Marks a typed fact as absent.
    #[must_use]
    pub fn with_absent<F: Fact>(mut self) -> Self {
        self.0.insert_typed::<F>(Presence::Absent);
        self
    }

    /// Marks a typed fact as unknown for query lowering.
    #[must_use]
    pub fn with_unknown<F: Fact>(mut self) -> Self {
        self.0.insert_typed::<F>(Presence::Unknown);
        self
    }

    /// Adds a runtime fact with any presence state.
    #[must_use]
    pub fn with_fact(mut self, fact: FactId, presence: Presence) -> Self {
        self.0.insert(fact, presence, None);
        self
    }

    /// Returns a fact's presence, defaulting to absent when omitted.
    #[must_use]
    pub fn presence(&self, fact: &FactId) -> Presence {
        self.0.presence(fact)
    }

    pub(crate) fn known_entries(&self) -> impl Iterator<Item = (&FactId, Presence)> {
        self.0
            .iter()
            .filter(|(_fact, presence)| *presence != Presence::Unknown)
    }
}

impl Extend<(FactId, Presence)> for PartialFacts {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = (FactId, Presence)>,
    {
        for (fact, presence) in iter {
            self.0.insert(fact, presence, None);
        }
    }
}

impl FromIterator<(FactId, Presence)> for PartialFacts {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = (FactId, Presence)>,
    {
        let mut facts = Self::new();
        facts.extend(iter);
        facts
    }
}
