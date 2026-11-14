//! Per-dialog INVITE admission (RFC 3261 §14). Reservations belong to actual
//! transactions, so dropping a future that borrows one cannot unlock it.
use super::{key::TransactionRole, TransactionState};
use crate::platform::sync::Mutex;
use crate::prelude::*;

#[derive(Default)]
pub(crate) struct InviteUsage {
    pub(crate) revision: u64,
    pub(crate) client_pending: bool,
    pub(crate) server_pending: bool,
    pub(crate) server_waiting_ack: usize,
}

enum Phase {
    ClientPending,
    ServerPending,
    ServerWaitingAck,
}

pub(crate) struct InviteReservation {
    usage: Arc<Mutex<InviteUsage>>,
    phase: Option<Phase>,
}

impl InviteReservation {
    pub(crate) fn acquire(
        usage: &Arc<Mutex<InviteUsage>>,
        role: TransactionRole,
    ) -> core::result::Result<Self, TransactionRole> {
        let mut state = usage.lock();
        if state.client_pending {
            return Err(TransactionRole::Client);
        }
        if state.server_pending
            || (role == TransactionRole::Client && state.server_waiting_ack != 0)
        {
            return Err(TransactionRole::Server);
        }
        state.revision += 1;
        let phase = match role {
            TransactionRole::Client => {
                state.client_pending = true;
                Phase::ClientPending
            }
            TransactionRole::Server => {
                state.server_pending = true;
                Phase::ServerPending
            }
        };
        Ok(Self {
            usage: usage.clone(),
            phase: Some(phase),
        })
    }

    pub(crate) fn transition(&mut self, state: &TransactionState) {
        match (&self.phase, state) {
            // Accepted is the RFC 6026 client retransmission window, after
            // the final 2xx. It must not prevent re-INVITEs for another 64*T1.
            (
                Some(Phase::ClientPending),
                TransactionState::Completed | TransactionState::Accepted,
            )
            | (_, TransactionState::Confirmed | TransactionState::Terminated) => self.release(),
            (
                Some(Phase::ServerPending),
                TransactionState::Completed | TransactionState::Accepted,
            ) => {
                let mut usage = self.usage.lock();
                usage.revision += 1;
                usage.server_pending = false;
                usage.server_waiting_ack += 1;
                self.phase = Some(Phase::ServerWaitingAck);
            }
            _ => (),
        }
    }

    fn release(&mut self) {
        if let Some(phase) = self.phase.take() {
            let mut usage = self.usage.lock();
            usage.revision += 1;
            match phase {
                Phase::ClientPending => usage.client_pending = false,
                Phase::ServerPending => usage.server_pending = false,
                Phase::ServerWaitingAck => usage.server_waiting_ack -= 1,
            }
        }
    }
}

impl Drop for InviteReservation {
    fn drop(&mut self) {
        self.release();
    }
}
