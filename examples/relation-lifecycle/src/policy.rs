//! Application policy and complete decision audit construction.
use gatekeep::policy;
use std::collections::BTreeMap;
use std::result::Result as StdResult;

use gatekeep::{
    AuditEntry, BindingProvenance, Condition, Decision, DecisionAuditId, DecisionAuditOccurrence,
    EffectKind, FactResolution, FactResolutionEvidence, FactResolutionMetadata, KnownFacts, Locale,
    Policy, PolicyAnchor, PolicyId, SubjectRef, SubjectSlot, TenantBinding, TenantId,
    TrustedServiceBinding,
};
use time::OffsetDateTime;

use crate::Result;

pub fn admission_policy() -> Result<Policy<()>> {
    Ok(policy::grant(
        (),
        Condition::Not(Box::new(Condition::Any(
            ["blocks-forward", "blocks-reverse", "restricted"]
                .into_iter()
                .map(gatekeep::FactId::new)
                .collect::<StdResult<Vec<_>, _>>()?
                .into_iter()
                .map(Condition::Has)
                .collect(),
        ))),
    ))
}

pub struct DecisionContext<'a> {
    pub tenant: &'a str,
    pub principal: &'a str,
    pub target: &'a str,
    pub id: &'a str,
    pub at: OffsetDateTime,
}

pub fn audit(
    context: &DecisionContext<'_>,
    policy: &Policy<()>,
    facts: KnownFacts,
    decision: &Decision<()>,
) -> Result<AuditEntry> {
    let tenant = TenantId::new(context.tenant)?;
    let trace = decision.to_trace()?;
    let provenance = FactResolutionMetadata::new(
        BindingProvenance::new("synthetic.locked-application-and-relations")?,
        None,
        None,
    );
    let resolution = FactResolution::new(facts, Some(provenance), context.at)?;
    Ok(AuditEntry::new(
        DecisionAuditOccurrence::new(DecisionAuditId::new(context.id)?, context.at)?,
        None,
        PolicyAnchor::new(PolicyId::new("synthetic-admission")?, policy.hash()?),
        if decision.is_permit() {
            EffectKind::Permit
        } else {
            EffectKind::Deny
        },
        decision.obligations.clone(),
        trace.consulted.clone(),
        trace.decisive.clone(),
        decision.denial_reason()?,
        trace,
        TenantBinding::TrustedService(TrustedServiceBinding::new(
            tenant.clone(),
            "synthetic-consumer",
        )?),
        FactResolutionEvidence::from_resolution(&resolution)?,
        tenant,
        SubjectRef::new("account", context.principal)?,
        BTreeMap::from([(
            SubjectSlot::new("recipient")?,
            SubjectRef::new("account", context.target)?,
        )]),
        Locale::new("en")?,
    )?)
}
