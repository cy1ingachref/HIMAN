use serde::{Deserialize, Serialize};

/// A device identity. The string form is stable across restarts and is what
/// the presence manager keys on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId(pub String);

impl DeviceId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for DeviceId {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

/// What kind of device this is. Determines the default tool whitelist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceClass {
    /// Windows / Linux workstation. Full Tier 1 tool set plus host commands.
    Pc,
    /// Android phone. Tier 1 plus notification and approval tools.
    Phone,
    /// Raspberry Pi or router. Read-only diagnostics by default.
    Embedded,
}

impl DeviceClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceClass::Pc => "pc",
            DeviceClass::Phone => "phone",
            DeviceClass::Embedded => "embedded",
        }
    }
}

/// Static description of a device, registered at connect time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: DeviceId,
    pub class: DeviceClass,
    /// Human label shown in the UI, e.g. "Ashe's PC".
    pub label: String,
    /// Ed25519 verifying key, base64url (no padding), of the device's identity.
    pub verifying_key: String,
}
