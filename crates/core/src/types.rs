macro_rules! fixed_id {
    ($name:ident, $size:expr) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub [u8; $size]);

        impl $name {
            #[must_use]
            pub const fn new(value: [u8; $size]) -> Self {
                Self(value)
            }

            #[must_use]
            pub fn is_zero(self) -> bool {
                self.0.iter().all(|byte| *byte == 0)
            }
        }
    };
}

fixed_id!(SessionId, 16);
fixed_id!(InteractionId, 16);
fixed_id!(Nonce, 16);
fixed_id!(ChallengeId, 16);
fixed_id!(GrantId, 16);
fixed_id!(EffectId, 16);
fixed_id!(ActorId, 32);
fixed_id!(KeyId, 32);
fixed_id!(Digest, 32);
