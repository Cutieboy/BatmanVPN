use std::{
    collections::HashMap,
    fmt,
    net::Ipv4Addr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
};

use mousevpn_config::{decode_public_key, encode_public_key};
use mousevpn_crypto::{KeyPair, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

use crate::registry_store::{
    load_devices, next_address, persist_devices, validate_devices, validate_name, RegistryError,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DevicePlatform {
    Android,
    Linux,
}

impl fmt::Display for DevicePlatform {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Android => formatter.write_str("android"),
            Self::Linux => formatter.write_str("linux"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceRecord {
    pub name: String,
    pub platform: DevicePlatform,
    pub public_key: String,
    pub address: Ipv4Addr,
}

#[derive(Clone)]
pub struct DeviceLease {
    pub name: String,
    pub address: Ipv4Addr,
    pub public_key: PublicKey,
    pub authorization: DeviceAuthorization,
}

#[derive(Clone)]
pub struct DeviceAuthorization(Arc<AtomicBool>);

impl DeviceAuthorization {
    fn active() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn revoke(&self) {
        self.0.store(false, Ordering::Release);
    }
}

pub struct SeedDevice {
    pub name: String,
    pub public_key: PublicKey,
    pub address: Ipv4Addr,
}

pub struct ProvisionedDevice {
    pub record: DeviceRecord,
    pub private_key: SecretKey,
}

struct DeviceRegistry {
    path: PathBuf,
    tunnel_address: Ipv4Addr,
    prefix_len: u8,
    devices: Vec<DeviceRecord>,
    leases: HashMap<PublicKey, DeviceLease>,
}

#[derive(Clone)]
pub struct SharedDeviceRegistry(Arc<RwLock<DeviceRegistry>>);

impl SharedDeviceRegistry {
    /// Opens the persistent registry, seeding it from the server config once.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid seed data, insecure permissions, or I/O failures.
    pub fn open(
        path: impl Into<PathBuf>,
        seeds: Vec<SeedDevice>,
        tunnel_address: Ipv4Addr,
        prefix_len: u8,
    ) -> Result<Self, RegistryError> {
        let path = path.into();
        let devices = if path.exists() {
            load_devices(&path)?
        } else {
            seeds
                .into_iter()
                .map(|seed| DeviceRecord {
                    name: seed.name,
                    platform: DevicePlatform::Linux,
                    public_key: encode_public_key(&seed.public_key),
                    address: seed.address,
                })
                .collect()
        };
        validate_devices(&devices, tunnel_address, prefix_len)?;
        let leases = build_leases(&devices)?;
        let registry = DeviceRegistry {
            path,
            tunnel_address,
            prefix_len,
            devices,
            leases,
        };
        if !registry.path.exists() {
            persist_devices(&registry.path, &registry.devices)?;
        }
        Ok(Self(Arc::new(RwLock::new(registry))))
    }

    /// Returns a snapshot of all registered devices.
    ///
    /// # Errors
    ///
    /// Returns an error if the registry lock is poisoned.
    pub fn list(&self) -> Result<Vec<DeviceRecord>, RegistryError> {
        Ok(self.read()?.devices.clone())
    }

    #[must_use]
    pub fn authorize(&self, public_key: &PublicKey) -> Option<DeviceLease> {
        self.0.read().ok()?.leases.get(public_key).cloned()
    }

    /// Creates and persists a separately revocable device key.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid name, exhausted addresses, key generation, or persistence.
    pub fn provision(
        &self,
        name: &str,
        platform: DevicePlatform,
    ) -> Result<ProvisionedDevice, RegistryError> {
        let name = name.trim().to_owned();
        validate_name(&name)?;
        let keys = KeyPair::generate().map_err(|error| RegistryError::new(error.to_string()))?;
        let mut registry = self.write()?;
        let address = next_address(
            &registry.devices,
            registry.tunnel_address,
            registry.prefix_len,
        )?;
        let record = DeviceRecord {
            name,
            platform,
            public_key: encode_public_key(&keys.public),
            address,
        };
        let mut next = registry.devices.clone();
        next.push(record.clone());
        persist_devices(&registry.path, &next)?;
        registry.devices = next;
        registry.leases.insert(
            keys.public,
            DeviceLease {
                name: record.name.clone(),
                address: record.address,
                public_key: keys.public,
                authorization: DeviceAuthorization::active(),
            },
        );
        Ok(ProvisionedDevice {
            record,
            private_key: keys.secret,
        })
    }

    /// Permanently removes a public key and disables its active sessions.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid key, the final remaining device, or persistence failure.
    pub fn revoke(&self, public_key: &str) -> Result<bool, RegistryError> {
        let decoded =
            decode_public_key(public_key).map_err(|error| RegistryError::new(error.to_string()))?;
        let mut registry = self.write()?;
        let mut next = registry.devices.clone();
        let before = next.len();
        next.retain(|device| device.public_key != public_key);
        if next.len() == before {
            return Ok(false);
        }
        if next.is_empty() {
            return Err(RegistryError::new(
                "at least one device must remain authorized",
            ));
        }
        persist_devices(&registry.path, &next)?;
        registry.devices = next;
        if let Some(lease) = registry.leases.remove(&decoded) {
            lease.authorization.revoke();
        }
        Ok(true)
    }

    fn read(&self) -> Result<std::sync::RwLockReadGuard<'_, DeviceRegistry>, RegistryError> {
        self.0
            .read()
            .map_err(|_| RegistryError::new("device registry lock is poisoned"))
    }

    fn write(&self) -> Result<std::sync::RwLockWriteGuard<'_, DeviceRegistry>, RegistryError> {
        self.0
            .write()
            .map_err(|_| RegistryError::new("device registry lock is poisoned"))
    }
}

fn build_leases(
    devices: &[DeviceRecord],
) -> Result<HashMap<PublicKey, DeviceLease>, RegistryError> {
    devices
        .iter()
        .map(|device| {
            let public_key = decode_public_key(&device.public_key)
                .map_err(|error| RegistryError::new(error.to_string()))?;
            Ok((
                public_key,
                DeviceLease {
                    name: device.name.clone(),
                    address: device.address,
                    public_key,
                    authorization: DeviceAuthorization::active(),
                },
            ))
        })
        .collect()
}
