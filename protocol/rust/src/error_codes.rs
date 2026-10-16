//! Error codes shared by every channel (docs/protocol.md section 6).

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    Unauthorized,
    NotPaired,
    CapabilityDisabled,
    ConfirmRequired,
    RateLimited,
    LockedOut,
    InvalidArgs,
    NotFound,
    Busy,
    Unsupported,
    TransportError,
    Internal,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::Unauthorized => "UNAUTHORIZED",
            ErrorCode::NotPaired => "NOT_PAIRED",
            ErrorCode::CapabilityDisabled => "CAPABILITY_DISABLED",
            ErrorCode::ConfirmRequired => "CONFIRM_REQUIRED",
            ErrorCode::RateLimited => "RATE_LIMITED",
            ErrorCode::LockedOut => "LOCKED_OUT",
            ErrorCode::InvalidArgs => "INVALID_ARGS",
            ErrorCode::NotFound => "NOT_FOUND",
            ErrorCode::Busy => "BUSY",
            ErrorCode::Unsupported => "UNSUPPORTED",
            ErrorCode::TransportError => "TRANSPORT_ERROR",
            ErrorCode::Internal => "INTERNAL",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "UNAUTHORIZED" => ErrorCode::Unauthorized,
            "NOT_PAIRED" => ErrorCode::NotPaired,
            "CAPABILITY_DISABLED" => ErrorCode::CapabilityDisabled,
            "CONFIRM_REQUIRED" => ErrorCode::ConfirmRequired,
            "RATE_LIMITED" => ErrorCode::RateLimited,
            "LOCKED_OUT" => ErrorCode::LockedOut,
            "INVALID_ARGS" => ErrorCode::InvalidArgs,
            "NOT_FOUND" => ErrorCode::NotFound,
            "BUSY" => ErrorCode::Busy,
            "UNSUPPORTED" => ErrorCode::Unsupported,
            "TRANSPORT_ERROR" => ErrorCode::TransportError,
            "INTERNAL" => ErrorCode::Internal,
            _ => return None,
        })
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ErrorCode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        // Forward compatibility: unknown codes are treated as INTERNAL
        // (docs/protocol.md section 6).
        Ok(ErrorCode::from_str(&s).unwrap_or(ErrorCode::Internal))
    }
}
