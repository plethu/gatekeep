use crate::{Decision, DecisiveClause, DenyShape, Presence};

/// Who may receive an explanation. Audit output contains internal fact names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplanationAudience {
    /// Minimal response, including generic text for hidden denials.
    Public,
    /// Internal inspection of the recorded evaluation, without provider reruns.
    Audit,
}

impl<O> Decision<O> {
    /// Formats the observed decision for an explicitly selected audience.
    ///
    /// Audit explanations reveal stable check names and boolean observations.
    /// They never capture Debug output from the principal, resource or outcome.
    /// Unconsulted clauses are not reconstructed from a trace or reevaluated.
    #[must_use]
    pub fn explain(&self, audience: ExplanationAudience) -> String {
        let public = match &self.trace.decisive {
            DecisiveClause::Deny {
                shape: DenyShape::Hidden,
                ..
            } => "not found",
            _ if self.is_permit() => "permitted",
            _ => "denied",
        };
        if audience == ExplanationAudience::Public {
            return public.to_owned();
        }

        let mut output = format!(
            "{}\n",
            if self.is_permit() {
                "permitted"
            } else {
                "denied"
            }
        );
        for (fact, presence) in &self.trace.consulted {
            let value = match presence {
                Presence::Present => "true",
                Presence::Absent => "false",
                Presence::Unknown => "deferred",
            };
            output.push_str("  ");
            output.push_str(fact.as_str());
            output.push_str(": ");
            output.push_str(value);
            output.push('\n');
        }

        let label = match &self.trace.decisive {
            DecisiveClause::Permit { label, .. } | DecisiveClause::Deny { label, .. } => label,
        };
        if let Some(label) = label {
            output.push_str("decisive clause: ");
            output.push_str(label.as_str());
            output.push('\n');
        }

        output.push_str("Only consulted facts are shown; other checks were not reconstructed.");
        output
    }
}
