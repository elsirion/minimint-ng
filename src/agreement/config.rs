use super::AgreementError;
use fedimint_aleph_bft::{Config, DelayConfig, NodeCount, NodeIndex};
use std::{sync::Arc, time::Duration};
pub fn ordinary_delays(rounds_per_session: u16, round_delay_ms: u64) -> DelayConfig {
    DelayConfig {
        tick_interval: Duration::from_millis(10),
        unit_rebroadcast_interval_min: Duration::from_secs(15),
        unit_rebroadcast_interval_max: Duration::from_secs(20),
        unit_creation_delay: Arc::new(move |round| {
            if round == 0 {
                Duration::ZERO
            } else {
                Duration::from_millis(
                    (round_delay_ms as f64
                        * 1.02f64
                            .powf(round.saturating_sub(usize::from(rounds_per_session)) as f64))
                    .round() as u64,
                )
            }
        }),
        coord_request_delay: Arc::new(|retry| {
            Duration::from_millis(match retry {
                0 => 0,
                1 => 50,
                2 => 1000,
                _ => 3000u64.saturating_mul(retry.saturating_sub(2) as u64),
            })
        }),
        coord_request_recipients: Arc::new(|retry| if retry <= 2 { 3 } else { 1 }),
        parent_request_delay: Arc::new(|_| Duration::from_secs(3)),
        parent_request_recipients: Arc::new(|_| 1),
        newest_request_delay: Arc::new(|_| Duration::from_secs(3)),
    }
}
pub fn session_config(
    count: usize,
    local: crate::protocol::PeerId,
    session: u64,
    rounds: u16,
    delay_ms: u64,
) -> Result<Config, AgreementError> {
    if !(4..=65_536).contains(&count) || usize::from(local.0) >= count {
        return Err(AgreementError::InvalidConfig);
    }
    let max_round = rounds
        .checked_add(1000)
        .ok_or(AgreementError::InvalidConfig)?;
    fedimint_aleph_bft::create_config(
        NodeCount(count),
        NodeIndex(usize::from(local.0)),
        session,
        max_round,
        ordinary_delays(rounds, delay_ms),
        Duration::from_secs(10 * 365 * 24 * 60 * 60),
    )
    .map_err(|_| AgreementError::InvalidConfig)
}
