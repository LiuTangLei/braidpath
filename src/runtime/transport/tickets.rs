//! Server resumption tickets that survive a restart without becoming reusable.
//!
//! rustls accepts 0-RTT data only on stateful resumption and takes each ticket
//! out of the store on use; that single use is the replay defence. This store
//! keeps the contract across restarts: a take is appended to a journal and
//! flushed to stable storage before the ticket reaches the handshake, so a
//! replayed first flight finds the ticket consumed even after a crash. An issue
//! record lost before it is flushed only costs one full handshake.
//!
//! An exclusive lock beside the journal keeps a second server process from
//! holding the same tickets in its own memory. The journal is bound to the
//! server certificate and discarded when it changes.

use anyhow::{Context, Result};
use std::{
    collections::{HashMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::warn;

const MAGIC: &[u8] = b"braidpath-tickets\x01";
const ISSUE: u8 = 1;
const TAKE: u8 = 2;
/// rustls issues stateful TLS 1.3 tickets for 24 hours.
const LIFETIME_SECS: u64 = 24 * 60 * 60;
const MAX_KEY: usize = 255;
const MAX_VALUE: usize = 16 * 1024;

pub struct Journal {
    path: PathBuf,
    identity: Vec<u8>,
    capacity: usize,
    state: Mutex<State>,
    _lock: File,
}

struct State {
    live: HashMap<Vec<u8>, (u64, Vec<u8>)>,
    /// Issue order for eviction; may name keys already taken.
    order: VecDeque<Vec<u8>>,
    /// None after a failed rewrite: tickets are then refused, never reused.
    file: Option<File>,
    records: usize,
}

impl std::fmt::Debug for Journal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal").field("path", &self.path).finish()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn fresh(issued: u64, now: u64) -> bool {
    issued <= now.saturating_add(60) && now.saturating_sub(issued) < LIFETIME_SECS
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

fn create(path: &Path, append: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).write(true);
    if append {
        options.append(true);
    } else {
        options.truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn issue_record(key: &[u8], issued: u64, value: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(15 + key.len() + value.len());
    record.push(ISSUE);
    record.push(key.len() as u8);
    record.extend_from_slice(key);
    record.extend_from_slice(&issued.to_be_bytes());
    record.extend_from_slice(&(value.len() as u32).to_be_bytes());
    record.extend_from_slice(value);
    record
}

fn take_record(key: &[u8]) -> Vec<u8> {
    let mut record = vec![TAKE, key.len() as u8];
    record.extend_from_slice(key);
    record
}

/// Replay the journal in order. A torn or invalid tail ends it.
fn replay(bytes: &[u8], state: &mut State) {
    let mut at = 0;
    let mut take = |n: usize| {
        let field = bytes.get(at..at + n)?;
        at += n;
        Some(field)
    };
    while let Some(&[tag]) = take(1) {
        let Some(&[len]) = take(1) else { return };
        let Some(key) = take(len as usize) else {
            return;
        };
        match tag {
            ISSUE => {
                let Some(issued) = take(8) else { return };
                let Some(len) = take(4) else { return };
                let len = u32::from_be_bytes(len.try_into().unwrap()) as usize;
                if len > MAX_VALUE {
                    return;
                }
                let Some(value) = take(len) else { return };
                let issued = u64::from_be_bytes(issued.try_into().unwrap());
                state.live.insert(key.to_vec(), (issued, value.to_vec()));
                state.order.push_back(key.to_vec());
            }
            TAKE => {
                state.live.remove(key);
            }
            _ => return,
        }
    }
}

impl Journal {
    /// Load `path`, keeping fresh unused tickets issued for `identity`, and
    /// rewrite it compactly. Fails if another process holds the journal.
    pub fn open(path: &Path, identity: &[u8], capacity: usize) -> Result<Self> {
        let lock = create(&with_suffix(path, ".lock"), true).context("ticket journal lock")?;
        lock_exclusive(&lock, path)?;
        let mut state = State {
            live: HashMap::new(),
            order: VecDeque::new(),
            file: None,
            records: 0,
        };
        match fs::read(path) {
            Ok(bytes) => {
                let header = [MAGIC, &(identity.len() as u32).to_be_bytes(), identity].concat();
                if let Some(records) = bytes.strip_prefix(header.as_slice()) {
                    replay(records, &mut state);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("ticket journal"),
        }
        let journal = Self {
            path: path.to_owned(),
            identity: identity.to_owned(),
            capacity,
            state: Mutex::new(State {
                file: None,
                ..state
            }),
            _lock: lock,
        };
        {
            let mut state = journal.state.lock().expect("ticket journal");
            let now = now();
            state.live.retain(|_, (issued, _)| fresh(*issued, now));
            journal.evict(&mut state);
            journal.rewrite(&mut state).context("ticket journal")?;
        }
        Ok(journal)
    }

    pub fn len(&self) -> usize {
        self.state.lock().expect("ticket journal").live.len()
    }

    fn evict(&self, state: &mut State) {
        while state.live.len() > self.capacity {
            let Some(key) = state.order.pop_front() else {
                break;
            };
            state.live.remove(&key);
        }
    }

    /// Replace the journal with the live tickets. A crash leaves either file,
    /// and both record every take flushed so far.
    fn rewrite(&self, state: &mut State) -> std::io::Result<()> {
        let live = &state.live;
        state.order.retain(|key| live.contains_key(key));
        let mut bytes = [
            MAGIC,
            &(self.identity.len() as u32).to_be_bytes(),
            &self.identity,
        ]
        .concat();
        for key in &state.order {
            let (issued, value) = &state.live[key];
            bytes.extend(issue_record(key, *issued, value));
        }
        let temporary = with_suffix(&self.path, ".tmp");
        let mut file = create(&temporary, false)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        state.file = None;
        fs::rename(&temporary, &self.path)?;
        // The rename must be durable before later takes are appended to the
        // new file; otherwise a crash could restore the old one without them.
        let directory = match self.path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        File::open(directory)?.sync_all()?;
        state.file = Some(create(&self.path, true)?);
        state.records = state.live.len();
        Ok(())
    }

    fn append(&self, state: &mut State, record: &[u8], durable: bool) -> bool {
        let Some(file) = state.file.as_mut() else {
            return false;
        };
        let written = file
            .write_all(record)
            .and_then(|()| if durable { file.sync_data() } else { Ok(()) });
        if let Err(error) = written {
            warn!(%error, path = %self.path.display(), "ticket journal write failed");
            return false;
        }
        state.records += 1;
        if state.records > self.capacity.max(1) * 4
            && let Err(error) = self.rewrite(state)
        {
            // Past the rename the old journal may return after a crash, so
            // appending to the new one could lose takes: refuse tickets instead.
            warn!(%error, path = %self.path.display(), "ticket journal rewrite failed");
            state.records = 0;
        }
        true
    }
}

impl rustls::server::StoresServerSessions for Journal {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        if key.len() > MAX_KEY || value.len() > MAX_VALUE {
            return false;
        }
        let issued = now();
        let mut state = self.state.lock().expect("ticket journal");
        // Without the issue record a restart forgets the ticket; that is safe.
        self.append(&mut state, &issue_record(&key, issued, &value), false);
        state.order.push_back(key.clone());
        state.live.insert(key, (issued, value));
        self.evict(&mut state);
        true
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let state = self.state.lock().expect("ticket journal");
        let (issued, value) = state.live.get(key)?;
        fresh(*issued, now()).then(|| value.clone())
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        let mut state = self.state.lock().expect("ticket journal");
        let (issued, value) = state.live.remove(key)?;
        // Release the ticket only once its use is on stable storage.
        (fresh(issued, now()) && self.append(&mut state, &take_record(key), true)).then_some(value)
    }

    fn can_cache(&self) -> bool {
        true
    }
}

#[cfg(unix)]
fn lock_exclusive(file: &File, path: &Path) -> Result<()> {
    rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .with_context(|| format!("ticket journal {} is in use", path.display()))
}

#[cfg(not(unix))]
fn lock_exclusive(_: &File, _: &Path) -> Result<()> {
    anyhow::bail!("ticket journal is not supported on this platform")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use rustls::server::StoresServerSessions;

    fn journal(dir: &Path) -> Journal {
        Journal::open(&dir.join("tickets"), b"identity", 8).unwrap()
    }

    #[test]
    fn unused_tickets_survive_reopening_and_taken_ones_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let store = journal(dir.path());
        assert!(store.put(b"a".to_vec(), b"one".to_vec()));
        assert!(store.put(b"b".to_vec(), b"two".to_vec()));
        assert_eq!(store.take(b"a").as_deref(), Some(&b"one"[..]));
        assert_eq!(store.take(b"a"), None);
        drop(store);
        let store = journal(dir.path());
        assert_eq!(store.take(b"a"), None);
        assert_eq!(store.get(b"b").as_deref(), Some(&b"two"[..]));
        assert_eq!(store.take(b"b").as_deref(), Some(&b"two"[..]));
        drop(store);
        assert_eq!(journal(dir.path()).len(), 0);
    }

    #[test]
    fn a_second_holder_is_refused_and_another_identity_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = journal(dir.path());
        store.put(b"a".to_vec(), b"one".to_vec());
        assert!(Journal::open(&dir.path().join("tickets"), b"identity", 8).is_err());
        drop(store);
        let other = Journal::open(&dir.path().join("tickets"), b"rotated", 8).unwrap();
        assert_eq!(other.len(), 0);
        drop(other);
        // The rotated identity rewrote the journal.
        assert_eq!(journal(dir.path()).len(), 0);
    }

    #[test]
    fn capacity_rewrites_and_a_torn_tail_stay_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tickets");
        let store = journal(dir.path());
        for i in 0u8..100 {
            store.put(vec![i], vec![i; 4]);
            if i % 2 == 0 {
                store.take(&[i]);
            }
        }
        assert_eq!(store.len(), 8);
        let size = fs::metadata(&path).unwrap().len();
        assert!(size < 64 * 21, "journal rewritten when it grows: {size}");
        drop(store);
        let mut torn = fs::read(&path).unwrap();
        torn.extend_from_slice(&issue_record(b"z", now(), b"value")[..5]);
        fs::write(&path, torn).unwrap();
        let store = journal(dir.path());
        assert_eq!(store.len(), 8);
        assert_eq!(store.get(b"z"), None);
        assert_eq!(store.get(&[99]).as_deref(), Some(&[99u8; 4][..]));
    }

    #[test]
    fn expired_tickets_are_dropped_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tickets");
        let header = [MAGIC, &8u32.to_be_bytes(), b"identity"].concat();
        let old = issue_record(b"old", now() - LIFETIME_SECS - 1, b"x");
        let new = issue_record(b"new", now(), b"y");
        fs::write(&path, [header, old, new].concat()).unwrap();
        let store = journal(dir.path());
        assert_eq!(store.take(b"old"), None);
        assert_eq!(store.take(b"new").as_deref(), Some(&b"y"[..]));
    }
}
