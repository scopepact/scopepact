use crate::error::{ProtocolError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InteractionState {
    Offered,
    Accepted,
    Running,
    Completed,
    Rejected,
    Cancelled,
    Failed,
    Expired,
}

impl InteractionState {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Accepted => "accepted",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Rejected | Self::Cancelled | Self::Failed | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Interaction {
    state: InteractionState,
}

impl Default for Interaction {
    fn default() -> Self {
        Self {
            state: InteractionState::Offered,
        }
    }
}

impl Interaction {
    #[must_use]
    pub const fn state(self) -> InteractionState {
        self.state
    }

    /// Applies one interaction lifecycle transition.
    ///
    /// # Errors
    ///
    /// Returns an error when the transition is not permitted or the current
    /// state is terminal.
    pub fn transition(&mut self, next: InteractionState) -> Result<()> {
        let valid = matches!(
            (self.state, next),
            (
                InteractionState::Offered,
                InteractionState::Accepted
                    | InteractionState::Rejected
                    | InteractionState::Cancelled
                    | InteractionState::Expired
            ) | (
                InteractionState::Accepted,
                InteractionState::Running
                    | InteractionState::Cancelled
                    | InteractionState::Failed
                    | InteractionState::Expired
            ) | (
                InteractionState::Running,
                InteractionState::Completed
                    | InteractionState::Cancelled
                    | InteractionState::Failed
                    | InteractionState::Expired
            )
        );
        if !valid {
            return Err(ProtocolError::InvalidTransition {
                from: self.state.name(),
                to: next.name(),
            });
        }
        self.state = next;
        Ok(())
    }
}
