use std::{
    collections::HashMap,
    fmt, fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

const TRAFFIC_VERSION: u8 = 1;
const SECONDS_PER_HOUR: u64 = 3_600;
const RETENTION_HOURS: u64 = 24 * 400;
pub(crate) const MAX_QUERY_HOURS: u64 = 24 * 31;

#[derive(Debug, Default)]
pub struct DeviceTrafficCounter {
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
}

impl DeviceTrafficCounter {
    pub fn add_upload(&self, bytes: u64) {
        self.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_download(&self, bytes: u64) {
        self.download_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

struct RegisteredCounter {
    name: RwLock<String>,
    counter: Arc<DeviceTrafficCounter>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TrafficBucket {
    hour: u64,
    public_key: String,
    name: String,
    upload_bytes: u64,
    download_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TrafficDocument {
    version: u8,
    buckets: Vec<TrafficBucket>,
}

impl Default for TrafficDocument {
    fn default() -> Self {
        Self {
            version: TRAFFIC_VERSION,
            buckets: Vec::new(),
        }
    }
}

struct TrafficStoreInner {
    path: PathBuf,
    counters: RwLock<HashMap<String, Arc<RegisteredCounter>>>,
    history: Mutex<TrafficDocument>,
}

#[derive(Clone)]
pub struct TrafficStore(Arc<TrafficStoreInner>);

impl TrafficStore {
    /// Opens or creates the durable hourly traffic store.
    ///
    /// # Errors
    ///
    /// Returns an error for insecure permissions, invalid data or I/O failures.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, TrafficError> {
        let path = path.into();
        let history = if path.exists() {
            ensure_private_permissions(&path)?;
            let document: TrafficDocument = toml::from_str(&fs::read_to_string(&path)?)?;
            if document.version != TRAFFIC_VERSION {
                return Err(TrafficError::new("unsupported traffic store version"));
            }
            document
        } else {
            TrafficDocument::default()
        };
        let store = Self(Arc::new(TrafficStoreInner {
            path,
            counters: RwLock::new(HashMap::new()),
            history: Mutex::new(history),
        }));
        if !store.0.path.exists() {
            store.persist_document(&TrafficDocument::default())?;
        }
        Ok(store)
    }

    #[must_use]
    pub fn counter(&self, public_key: &str, name: &str) -> Arc<DeviceTrafficCounter> {
        if let Some(registered) = self
            .0
            .counters
            .read()
            .ok()
            .and_then(|counters| counters.get(public_key).cloned())
        {
            if let Ok(mut current_name) = registered.name.write() {
                name.clone_into(&mut current_name);
            }
            return Arc::clone(&registered.counter);
        }
        let Ok(mut counters) = self.0.counters.write() else {
            return Arc::new(DeviceTrafficCounter::default());
        };
        let registered = counters
            .entry(public_key.to_owned())
            .or_insert_with(|| {
                Arc::new(RegisteredCounter {
                    name: RwLock::new(name.to_owned()),
                    counter: Arc::new(DeviceTrafficCounter::default()),
                })
            })
            .clone();
        Arc::clone(&registered.counter)
    }

    /// Persists pending counters in a background thread.
    pub fn spawn_flusher(&self, interval: Duration) {
        let store = self.clone();
        thread::spawn(move || loop {
            thread::sleep(interval);
            if let Err(error) = store.flush() {
                eprintln!("MouseVPN traffic persistence failed: {error}");
            }
        });
    }

    /// Moves current atomic counters into the durable hourly history.
    ///
    /// # Errors
    ///
    /// Returns an error if locks are poisoned or the atomic file replacement fails.
    pub fn flush(&self) -> Result<(), TrafficError> {
        self.flush_at(unix_seconds())
    }

    pub(crate) fn report(&self, hours: u64) -> Result<TrafficReport, TrafficError> {
        self.report_at(hours, unix_seconds())
    }

    fn flush_at(&self, now: u64) -> Result<(), TrafficError> {
        let pending = self.take_pending()?;
        if pending.is_empty() {
            return Ok(());
        }
        let current_hour = now / SECONDS_PER_HOUR;
        let mut history = self
            .0
            .history
            .lock()
            .map_err(|_| TrafficError::new("traffic history lock is poisoned"))?;
        let mut next = history.clone();
        merge_pending(&mut next.buckets, current_hour, &pending);
        let oldest = current_hour.saturating_sub(RETENTION_HOURS);
        next.buckets.retain(|bucket| bucket.hour >= oldest);
        if let Err(error) = self.persist_document(&next) {
            self.restore_pending(&pending);
            return Err(error);
        }
        *history = next;
        Ok(())
    }

    fn report_at(&self, hours: u64, now: u64) -> Result<TrafficReport, TrafficError> {
        let hours = hours.clamp(1, MAX_QUERY_HOURS);
        let current_hour = now / SECONDS_PER_HOUR;
        let mut buckets = self
            .0
            .history
            .lock()
            .map_err(|_| TrafficError::new("traffic history lock is poisoned"))?
            .buckets
            .clone();
        let pending = self.peek_pending()?;
        merge_pending(&mut buckets, current_hour, &pending);

        let series_start = current_hour.saturating_sub(hours - 1);
        let mut hourly = (series_start..=current_hour)
            .map(|hour| TrafficPoint {
                hour: hour * SECONDS_PER_HOUR,
                upload_bytes: 0,
                download_bytes: 0,
            })
            .collect::<Vec<_>>();
        let mut devices = HashMap::<String, DeviceTrafficSummary>::new();
        let mut hour_total = TrafficTotals::default();
        let mut day_total = TrafficTotals::default();
        let mut week_total = TrafficTotals::default();

        for bucket in buckets {
            let age = current_hour.saturating_sub(bucket.hour);
            if bucket.hour > current_hour || age >= 168 {
                continue;
            }
            let totals = TrafficTotals {
                upload_bytes: bucket.upload_bytes,
                download_bytes: bucket.download_bytes,
            };
            week_total.add(totals);
            if age < 24 {
                day_total.add(totals);
            }
            if age == 0 {
                hour_total.add(totals);
            }
            if bucket.hour >= series_start {
                let index = usize::try_from(bucket.hour - series_start)
                    .map_err(|_| TrafficError::new("traffic bucket index overflow"))?;
                hourly[index].add(totals);
                let device = devices.entry(bucket.public_key.clone()).or_insert_with(|| {
                    DeviceTrafficSummary {
                        public_key: bucket.public_key,
                        name: bucket.name.clone(),
                        upload_bytes: 0,
                        download_bytes: 0,
                    }
                });
                device.name = bucket.name;
                device.upload_bytes = device.upload_bytes.saturating_add(bucket.upload_bytes);
                device.download_bytes = device.download_bytes.saturating_add(bucket.download_bytes);
            }
        }
        let mut devices = devices.into_values().collect::<Vec<_>>();
        devices.sort_by(|left, right| {
            right
                .total_bytes()
                .cmp(&left.total_bytes())
                .then_with(|| left.name.cmp(&right.name))
        });
        Ok(TrafficReport {
            generated_at: now,
            selected_hours: hours,
            totals: TrafficPeriodTotals {
                hour: hour_total,
                day: day_total,
                week: week_total,
            },
            hourly,
            devices,
        })
    }

    fn take_pending(&self) -> Result<Vec<PendingTraffic>, TrafficError> {
        self.pending_with(|counter| {
            (
                counter.upload_bytes.swap(0, Ordering::AcqRel),
                counter.download_bytes.swap(0, Ordering::AcqRel),
            )
        })
    }

    fn peek_pending(&self) -> Result<Vec<PendingTraffic>, TrafficError> {
        self.pending_with(|counter| {
            (
                counter.upload_bytes.load(Ordering::Acquire),
                counter.download_bytes.load(Ordering::Acquire),
            )
        })
    }

    fn pending_with(
        &self,
        read: impl Fn(&DeviceTrafficCounter) -> (u64, u64),
    ) -> Result<Vec<PendingTraffic>, TrafficError> {
        let counters = self
            .0
            .counters
            .read()
            .map_err(|_| TrafficError::new("traffic counter lock is poisoned"))?;
        let mut pending = Vec::with_capacity(counters.len());
        for (public_key, registered) in counters.iter() {
            let (upload_bytes, download_bytes) = read(&registered.counter);
            if upload_bytes == 0 && download_bytes == 0 {
                continue;
            }
            let name = registered
                .name
                .read()
                .map_err(|_| TrafficError::new("traffic device name lock is poisoned"))?
                .clone();
            pending.push(PendingTraffic {
                public_key: public_key.clone(),
                name,
                upload_bytes,
                download_bytes,
            });
        }
        Ok(pending)
    }

    fn restore_pending(&self, pending: &[PendingTraffic]) {
        for item in pending {
            let counter = self.counter(&item.public_key, &item.name);
            counter.add_upload(item.upload_bytes);
            counter.add_download(item.download_bytes);
        }
    }

    fn persist_document(&self, document: &TrafficDocument) -> Result<(), TrafficError> {
        let parent = self
            .0
            .path
            .parent()
            .ok_or_else(|| TrafficError::new("traffic store has no parent directory"))?;
        fs::create_dir_all(parent)?;
        let encoded = toml::to_string_pretty(document)?;
        let mut temporary = NamedTempFile::new_in(parent)?;
        set_private_permissions(temporary.as_file())?;
        temporary.write_all(encoded.as_bytes())?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&self.0.path)
            .map_err(|error| TrafficError::new(error.error.to_string()))?;
        Ok(())
    }
}

#[derive(Clone)]
struct PendingTraffic {
    public_key: String,
    name: String,
    upload_bytes: u64,
    download_bytes: u64,
}

fn merge_pending(buckets: &mut Vec<TrafficBucket>, hour: u64, pending: &[PendingTraffic]) {
    for item in pending {
        if let Some(bucket) = buckets
            .iter_mut()
            .find(|bucket| bucket.hour == hour && bucket.public_key == item.public_key)
        {
            bucket.name.clone_from(&item.name);
            bucket.upload_bytes = bucket.upload_bytes.saturating_add(item.upload_bytes);
            bucket.download_bytes = bucket.download_bytes.saturating_add(item.download_bytes);
        } else {
            buckets.push(TrafficBucket {
                hour,
                public_key: item.public_key.clone(),
                name: item.name.clone(),
                upload_bytes: item.upload_bytes,
                download_bytes: item.download_bytes,
            });
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct TrafficTotals {
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

impl TrafficTotals {
    fn add(&mut self, other: Self) {
        self.upload_bytes = self.upload_bytes.saturating_add(other.upload_bytes);
        self.download_bytes = self.download_bytes.saturating_add(other.download_bytes);
    }
}

#[derive(Debug, Serialize)]
pub struct TrafficPeriodTotals {
    pub hour: TrafficTotals,
    pub day: TrafficTotals,
    pub week: TrafficTotals,
}

#[derive(Debug, Serialize)]
pub struct TrafficPoint {
    /// Start of the UTC hour as a Unix timestamp.
    pub hour: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

impl TrafficPoint {
    fn add(&mut self, totals: TrafficTotals) {
        self.upload_bytes = self.upload_bytes.saturating_add(totals.upload_bytes);
        self.download_bytes = self.download_bytes.saturating_add(totals.download_bytes);
    }
}

#[derive(Debug, Serialize)]
pub struct DeviceTrafficSummary {
    pub public_key: String,
    pub name: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

impl DeviceTrafficSummary {
    fn total_bytes(&self) -> u64 {
        self.upload_bytes.saturating_add(self.download_bytes)
    }
}

#[derive(Debug, Serialize)]
pub struct TrafficReport {
    pub generated_at: u64,
    pub selected_hours: u64,
    pub totals: TrafficPeriodTotals,
    pub hourly: Vec<TrafficPoint>,
    pub devices: Vec<DeviceTrafficSummary>,
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(unix)]
fn ensure_private_permissions(path: &Path) -> Result<(), TrafficError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(TrafficError::new(format!(
            "traffic store permissions are insecure: {mode:o}"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_permissions(_path: &Path) -> Result<(), TrafficError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(file: &fs::File) -> Result<(), TrafficError> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_file: &fs::File) -> Result<(), TrafficError> {
    Ok(())
}

#[derive(Debug)]
pub struct TrafficError(String);

impl TrafficError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for TrafficError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for TrafficError {}

impl From<std::io::Error> for TrafficError {
    fn from(error: std::io::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<toml::de::Error> for TrafficError {
    fn from(error: toml::de::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<toml::ser::Error> for TrafficError {
    fn from(error: toml::ser::Error) -> Self {
        Self::new(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::{TrafficStore, SECONDS_PER_HOUR};

    #[test]
    fn reports_and_reopens_hourly_traffic() {
        let temporary = TempDir::new().expect("temporary directory");
        let path = temporary.path().join("traffic.toml");
        let store = TrafficStore::open(&path).expect("traffic store");
        let alice = store.counter("alice-key", "Alice phone");
        alice.add_upload(1_000);
        alice.add_download(3_000);
        store
            .flush_at(100 * SECONDS_PER_HOUR)
            .expect("traffic flush");

        let reopened = TrafficStore::open(path).expect("reopened traffic store");
        let report = reopened
            .report_at(24, 100 * SECONDS_PER_HOUR + 10)
            .expect("traffic report");
        assert_eq!(report.totals.hour.upload_bytes, 1_000);
        assert_eq!(report.totals.day.download_bytes, 3_000);
        assert_eq!(report.devices.len(), 1);
        assert_eq!(report.devices[0].name, "Alice phone");
        assert_eq!(
            report.hourly.last().expect("current hour").upload_bytes,
            1_000
        );
    }

    #[test]
    fn includes_unflushed_counters_in_reports() {
        let temporary = TempDir::new().expect("temporary directory");
        let store =
            TrafficStore::open(temporary.path().join("traffic.toml")).expect("traffic store");
        let counter = store.counter("key", "Laptop");
        counter.add_upload(42);
        counter.add_download(84);

        let report = store
            .report_at(1, 10 * SECONDS_PER_HOUR)
            .expect("traffic report");
        assert_eq!(report.totals.hour.upload_bytes, 42);
        assert_eq!(report.totals.hour.download_bytes, 84);
    }
}
