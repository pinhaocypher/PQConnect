// Port settings
pub const PQCPORT: u16 = 42424;

// Misc constants
pub const EPOCH_DURATION_SECONDS: u64 = 30;
pub const MAX_CONNS: u32 = 1 << 16;
pub const TIDLEN: usize = 32;

// Message types
pub const HANDSHAKE_FAIL: &[u8] = b"\x03\x00";
pub const INITIATION_MSG: &[u8] = b"\x01\x00";
pub const TUNNEL_MSG: &[u8] = b"\x02\x00";
