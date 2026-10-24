//! How many accounts each operator is shown in a company's console, counted per window, so that an operator reading
//! far more than usual can be noticed.
//!
//! The counts are held with the request counters, in the store node's memory: they are a signal, not a record, and
//! the record of an address shown whole is the audit trail's.

use std::num::NonZeroU64;

use tessari_oauth_constants::{
    OPERATOR_READ_WINDOW_SECS, OPERATOR_READS_NOTICED, THROTTLE_WRITE_ATTEMPTS,
};
use tessari_oauth_types::{Actor, TenantId, Timestamp};

use super::model::Counters;
use super::service::{counter_key, noticed, window};
use super::{Limit, ThrottleService};
use crate::{Error, Result, retry};

/// An operator's account reads in the current window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorReads {
    /// Accounts shown to the operator in this window, this read's included.
    pub total: u64,
    /// Whether this read took the total to the number worth noticing; true once per window.
    pub noticed: bool,
}

impl ThrottleService {
    /// Count `accounts` shown to `operator` in `tenant`'s console at `now`.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses, or answers in a shape this crate cannot read.
    pub async fn operator_read(
        &self,
        tenant: &TenantId,
        operator: &Actor,
        accounts: u64,
        now: Timestamp,
    ) -> Result<OperatorReads> {
        let zero = Error::Invalid {
            record: "operator read count",
            reason: "a window or a threshold of zero",
        };
        let limit = Limit {
            requests: NonZeroU64::new(OPERATOR_READS_NOTICED).ok_or_else(|| zero.clone())?,
            window_secs: NonZeroU64::new(OPERATOR_READ_WINDOW_SECS).ok_or(zero)?,
        };
        let (index, left) = window(limit, now);
        let seconds = left.saturating_add(OPERATOR_READ_WINDOW_SECS);
        // A tenant id holds no `:`, so the operator's id, which may, comes last.
        let key = counter_key(
            "operator-reads",
            index,
            &format!("{}:{}", tenant.as_str(), operator.name()),
        );
        let total = retry::bounded(THROTTLE_WRITE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.count(
                self.tenancy.throttle(),
                Counters::Requests,
                &key,
                accounts,
                seconds,
            )
        })
        .await?;
        Ok(OperatorReads {
            total,
            noticed: noticed(total, accounts, OPERATOR_READS_NOTICED),
        })
    }
}
