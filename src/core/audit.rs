//! Aggregate module audits without inventing arithmetic rules inside modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    Overflow,
    Negative { net_assets_msat: i64 },
}
impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Overflow => "aggregate audit overflow",
            Self::Negative { .. } => "negative aggregate audit",
        })
    }
}
impl std::error::Error for AuditError {}
/// CON-005: call after every accepted item, including module consensus items.
/// Failure is fatal to consensus; it is not an ordinary item rejection.
pub fn require_nonnegative(
    contributions: impl IntoIterator<Item = i64>,
) -> Result<i64, AuditError> {
    let mut total = 0_i64;
    for contribution in contributions {
        total = total
            .checked_add(contribution)
            .ok_or(AuditError::Overflow)?;
    }
    if total < 0 {
        return Err(AuditError::Negative {
            net_assets_msat: total,
        });
    }
    Ok(total)
}
