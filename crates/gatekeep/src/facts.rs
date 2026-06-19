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
    fn insert(&mut self, fact: FactId, presence: Presence, value: Option<TraceValue>) {
        self.0.insert(fact, (presence, value));
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
        let mut facts = Facts::default();
        for (fact, presence) in entries {
            if presence == Presence::Unknown {
                return Err(GatekeepError::InvalidPolicyRecord {
                    reason: "known facts cannot contain unknown presence",
                });
            }
            facts.insert(fact, presence, None);
        }
        Ok(Self(facts))
    }

    pub(crate) fn from_known_entries(
        entries: impl IntoIterator<Item = (FactId, Presence)>,
    ) -> Self {
        let mut facts = Facts::default();
        for (fact, presence) in entries {
            if presence != Presence::Unknown {
                facts.insert(fact, presence, None);
            }
        }
        Self(facts)
    }

    /// Marks a typed fact as present.
    #[must_use]
    pub fn with_present<F: Fact>(mut self) -> Self {
        self.0.insert(
            FactId::from_trusted(F::ID.as_str()),
            Presence::Present,
            None,
        );
        self
    }

    /// Marks a typed fact as absent.
    #[must_use]
    pub fn with_absent<F: Fact>(mut self) -> Self {
        self.0
            .insert(FactId::from_trusted(F::ID.as_str()), Presence::Absent, None);
        self
    }

    /// Adds a runtime fact, rejecting `Presence::Unknown`.
    pub fn try_with_fact(mut self, fact: FactId, presence: Presence) -> GatekeepResult<Self> {
        if presence == Presence::Unknown {
            return Err(GatekeepError::InvalidPolicyRecord {
                reason: "known facts cannot contain unknown presence",
            });
        }
        self.0.insert(fact, presence, None);
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
        let mut facts = Facts::default();
        for (fact, presence) in entries {
            facts.insert(fact, presence, None);
        }
        Self(facts)
    }

    /// Marks a typed fact as present.
    #[must_use]
    pub fn with_present<F: Fact>(mut self) -> Self {
        self.0.insert(
            FactId::from_trusted(F::ID.as_str()),
            Presence::Present,
            None,
        );
        self
    }

    /// Marks a typed fact as absent.
    #[must_use]
    pub fn with_absent<F: Fact>(mut self) -> Self {
        self.0
            .insert(FactId::from_trusted(F::ID.as_str()), Presence::Absent, None);
        self
    }

    /// Marks a typed fact as unknown for query lowering.
    #[must_use]
    pub fn with_unknown<F: Fact>(mut self) -> Self {
        self.0.insert(
            FactId::from_trusted(F::ID.as_str()),
            Presence::Unknown,
            None,
        );
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
