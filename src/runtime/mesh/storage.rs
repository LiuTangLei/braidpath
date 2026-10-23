//! Startup-only identity handling and atomic, bounded restart caches.
use super::*;
use std::io::Write;

const IDENTITY: &str = "identity.json";
const STAGED: &str = ".braidpath-pending-";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    node: Node,
    key: ServerKey,
}

pub(super) fn atomic_write(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    let parent = path.parent().context("state file has no parent")?;
    let mut staged = tempfile::Builder::new()
        .prefix(STAGED)
        .tempfile_in(parent)?;
    // NamedTempFile creates owner-only files on Unix. Write and flush in the
    // destination directory before publishing; never truncate a live state file.
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    if replace {
        staged.persist(path)?;
    } else {
        staged.persist_noclobber(path)?;
    }
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn validate_key(key: &ServerKey) -> Result<()> {
    ensure!(
        key.client.version == 1 && valid_token(&key.client.token) && valid_token(&key.member_token),
        "invalid cluster key"
    );
    let certificates = rustls_pemfile::certs(&mut key.client.certificate.as_bytes())
        .collect::<std::io::Result<Vec<_>>>()?;
    let private_key = rustls_pemfile::private_key(&mut key.private_key.as_bytes())?
        .context("missing cluster private key")?;
    // Validate the complete imported key, including certificate/private-key
    // correspondence, before creating any durable identity or derived files.
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    Ok(())
}

fn materialize(path: &Path, bytes: &[u8]) -> Result<()> {
    match fs::read(path) {
        Ok(existing) => ensure!(
            existing == bytes,
            "state file conflicts with saved identity: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => private_write(path, bytes)?,
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn materialize_json<T: Serialize + DeserializeOwned + PartialEq>(
    path: &Path,
    value: &T,
) -> Result<()> {
    if path.try_exists()? {
        ensure!(
            read_json::<T>(path)? == *value,
            "state file conflicts with saved identity: {}",
            path.display()
        );
        Ok(())
    } else {
        write_json(path, value)
    }
}

pub(super) fn open_server(
    dir: &Path,
    node: &Node,
    join_key: Option<&Path>,
    joining: bool,
) -> Result<(ServerKey, Node, fs::File)> {
    private_dir(dir)?;
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(dir.join("server.lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .context("state directory is already used by another server")?;
    // Keep the file itself: unlinking a lock file lets another process lock a
    // different inode. The OS releases the lock even after a process crash.
    let identity_path = dir.join(IDENTITY);
    let saved = identity_path.exists();
    let mut identity: Identity = if saved {
        read_json(&identity_path)?
    } else if dir.join("server-key.json").exists() || dir.join("node.json").exists() {
        // Preserve complete pre-manifest identities. Partial legacy state
        // is rejected instead of silently minting replacement credentials.
        Identity {
            node: read_json(&dir.join("node.json"))?,
            key: read_json(&dir.join("server-key.json"))?,
        }
    } else {
        ensure!(
            fs::read_dir(dir)?.all(|entry| entry.is_ok_and(|e| {
                let name = e.file_name();
                name == "server.lock" || name.to_string_lossy().starts_with(STAGED)
            })),
            "unrecognized state files; refusing to replace credentials"
        );
        let key = if let Some(path) = join_key {
            read_json(path)?
        } else {
            ensure!(!joining, "first join requires --join-key");
            let certificate = rcgen::generate_simple_self_signed(vec![NAME.into()])?;
            ServerKey {
                client: ClientKey {
                    version: 1,
                    certificate: certificate.cert.pem(),
                    token: transport::hex(&rand::random::<[u8; 32]>()),
                },
                private_key: certificate.signing_key.serialize_pem(),
                member_token: transport::hex(&rand::random::<[u8; 32]>()),
            }
        };
        Identity {
            node: node.clone(),
            key,
        }
    };
    ensure!(
        identity.node.id == node.id,
        "node identity differs from saved state"
    );
    validate_key(&identity.key)?;
    if let Some(path) = join_key
        && path.try_exists()?
    {
        let supplied: ServerKey = read_json(path)?;
        ensure!(
            supplied == identity.key,
            "join key belongs to a different cluster"
        );
    }
    node.validate()?;
    let moved = identity.node.address != node.address;
    if moved {
        identity.node.incarnation = identity
            .node
            .incarnation
            .checked_add(1)
            .context("node incarnation exhausted")?;
        identity.node.address = node.address;
    }
    let node_path = dir.join("node.json");
    let derived = if node_path.try_exists()? {
        let derived: Node = read_json(&node_path)?;
        ensure!(
            derived.id == identity.node.id
                && (derived == identity.node || derived.incarnation < identity.node.incarnation),
            "node file conflicts with saved identity"
        );
        Some(derived)
    } else {
        None
    };
    if !saved || moved {
        // Publish the complete identity first. A crash before updating node.json
        // is repaired from this journal without incrementing the version again.
        let encoded = serde_json::to_vec(&identity)?;
        ensure!(encoded.len() <= MAX_BODY, "mesh state exceeds size limit");
        atomic_write(&identity_path, &encoded, saved)?;
    }
    // A once-imported key may be removed without breaking the original service
    // arguments. Persistent identity, not the enrollment file, owns a restart.
    install_client(dir, &identity.key.client)?;
    materialize(&dir.join("key.pem"), identity.key.private_key.as_bytes())?;
    materialize_json(&dir.join("server-key.json"), &identity.key)?;
    materialize_json(&dir.join("client-key.json"), &identity.key.client)?;
    if derived.as_ref() != Some(&identity.node) {
        atomic_write(
            &node_path,
            &serde_json::to_vec(&identity.node)?,
            derived.is_some(),
        )?;
    }
    Ok((identity.key, identity.node, lock))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> Node {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Node {
            id: "node".into(),
            address: "127.0.0.1:4433".parse().unwrap(),
            incarnation: 0,
        }
    }

    #[test]
    fn restart_keeps_identity_and_repairs_interrupted_materialization() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("node");
        let node = node();
        let (key, _, lock) = open_server(&dir, &node, None, false).unwrap();
        let before = fs::read(dir.join(IDENTITY)).unwrap();
        assert!(open_server(&dir, &node, None, false).is_err());
        drop(lock);
        for name in [
            "cert.pem",
            "key.pem",
            "token",
            "server-key.json",
            "client-key.json",
            "node.json",
        ] {
            fs::remove_file(dir.join(name)).unwrap();
        }
        // Enrollment input can be removed after import; service args still work.
        let (restored, _, lock) = open_server(
            &dir,
            &node,
            Some(&temp.path().join("removed-join-key")),
            true,
        )
        .unwrap();
        assert!(restored == key);
        assert_eq!(fs::read(dir.join(IDENTITY)).unwrap(), before);
        assert_eq!(
            fs::read_to_string(dir.join("token")).unwrap(),
            key.client.token
        );
        assert_eq!(
            fs::read_to_string(dir.join("key.pem")).unwrap(),
            key.private_key
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in [
                IDENTITY,
                "key.pem",
                "token",
                "server-key.json",
                "client-key.json",
            ] {
                assert_eq!(
                    fs::metadata(dir.join(name)).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        drop(lock);
        let mut changed = node.clone();
        changed.id = "other".into();
        assert!(open_server(&dir, &changed, None, false).is_err());
        assert_eq!(fs::read(dir.join(IDENTITY)).unwrap(), before);
    }

    #[test]
    fn invalid_import_cannot_poison_a_fresh_directory_or_replace_saved_identity() {
        let temp = tempfile::tempdir().unwrap();
        let node = node();
        let source = temp.path().join("source");
        let (mut key, _, lock) = open_server(&source, &node, None, false).unwrap();
        drop(lock);
        let input = temp.path().join("import.json");
        let pem = key.private_key.clone();
        // A valid but different private key must also fail before publication.
        key.private_key = rcgen::generate_simple_self_signed(vec![NAME.into()])
            .unwrap()
            .signing_key
            .serialize_pem();
        write_json(&input, &key).unwrap();
        let dir = temp.path().join("joined");
        assert!(open_server(&dir, &node, Some(&input), true).is_err());
        assert!(!dir.join(IDENTITY).exists());
        assert!(!dir.join("cert.pem").exists());
        key.private_key = pem;
        atomic_write(&input, &serde_json::to_vec(&key).unwrap(), true).unwrap();
        let (imported, _, lock) = open_server(&dir, &node, Some(&input), true).unwrap();
        assert!(imported == key);
        drop(lock);
        key.member_token = "b".repeat(64);
        atomic_write(&input, &serde_json::to_vec(&key).unwrap(), true).unwrap();
        assert!(open_server(&dir, &node, Some(&input), true).is_err());
        let (saved, _, _lock) = open_server(&dir, &node, None, false).unwrap();
        assert!(saved == imported);
    }

    #[test]
    fn complete_legacy_identity_is_adopted_without_rotating_keys() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("node");
        let node = node();
        let (key, _, lock) = open_server(&dir, &node, None, false).unwrap();
        drop(lock);
        fs::remove_file(dir.join(IDENTITY)).unwrap();
        fs::write(
            dir.join("server-key.json"),
            serde_json::to_vec(&key).unwrap(),
        )
        .unwrap();
        fs::write(dir.join("node.json"), serde_json::to_vec(&node).unwrap()).unwrap();
        let (adopted, _, _lock) = open_server(&dir, &node, None, false).unwrap();
        assert!(adopted == key);
        assert!(dir.join(IDENTITY).exists());
    }

    #[test]
    fn address_migration_preserves_keys_and_recovers_an_interrupted_node_file() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("node");
        let original = node();
        let (key, saved, lock) = open_server(&dir, &original, None, false).unwrap();
        assert_eq!(saved, original);
        let original_node = fs::read(dir.join("node.json")).unwrap();
        let key_files: Vec<_> = [
            "cert.pem",
            "key.pem",
            "token",
            "client-key.json",
            "server-key.json",
        ]
        .into_iter()
        .map(|name| (name, fs::read(dir.join(name)).unwrap()))
        .collect();
        let mut requested = original.clone();
        requested.address.set_port(4434);
        // The existing process must retain exclusive ownership during a move.
        assert!(open_server(&dir, &requested, None, false).is_err());
        drop(lock);
        let (moved_key, moved, lock) = open_server(&dir, &requested, None, false).unwrap();
        assert!(moved_key == key);
        assert_eq!(moved.address, requested.address);
        assert_eq!(moved.incarnation, 1);
        let journal = fs::read(dir.join(IDENTITY)).unwrap();
        drop(lock);

        // Model a crash after identity publication but before node.json was
        // replaced: restart must repair this file and keep exactly version 1.
        atomic_write(&dir.join("node.json"), &original_node, true).unwrap();
        let (recovered_key, recovered, lock) = open_server(&dir, &requested, None, false).unwrap();
        assert!(recovered_key == key);
        assert_eq!(recovered, moved);
        assert_eq!(fs::read(dir.join(IDENTITY)).unwrap(), journal);
        assert_eq!(read_json::<Node>(&dir.join("node.json")).unwrap(), moved);
        for (name, bytes) in key_files {
            assert_eq!(fs::read(dir.join(name)).unwrap(), bytes);
        }
        drop(lock);
        let (_, returned, _lock) = open_server(&dir, &original, None, false).unwrap();
        assert_eq!(returned.address, original.address);
        assert_eq!(returned.incarnation, 2);
    }

    #[test]
    fn migration_rejects_wrong_keys_and_overflow_before_mutating_identity() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("node");
        let original = node();
        let (mut wrong_key, _, lock) = open_server(&dir, &original, None, false).unwrap();
        drop(lock);
        let mut requested = original.clone();
        requested.address.set_port(4434);
        let before = fs::read(dir.join(IDENTITY)).unwrap();
        wrong_key.member_token = if wrong_key.member_token == "b".repeat(64) {
            "c".repeat(64)
        } else {
            "b".repeat(64)
        };
        let key_path = temp.path().join("wrong-key.json");
        write_json(&key_path, &wrong_key).unwrap();
        assert!(open_server(&dir, &requested, Some(&key_path), true).is_err());
        assert_eq!(fs::read(dir.join(IDENTITY)).unwrap(), before);
        assert_eq!(read_json::<Node>(&dir.join("node.json")).unwrap(), original);

        let mut identity: Identity = read_json(&dir.join(IDENTITY)).unwrap();
        identity.node.incarnation = u64::MAX;
        atomic_write(
            &dir.join(IDENTITY),
            &serde_json::to_vec(&identity).unwrap(),
            true,
        )
        .unwrap();
        atomic_write(
            &dir.join("node.json"),
            &serde_json::to_vec(&identity.node).unwrap(),
            true,
        )
        .unwrap();
        let before = fs::read(dir.join(IDENTITY)).unwrap();
        assert!(open_server(&dir, &requested, None, false).is_err());
        assert_eq!(fs::read(dir.join(IDENTITY)).unwrap(), before);
        assert_eq!(
            read_json::<Node>(&dir.join("node.json")).unwrap(),
            identity.node
        );
    }

    #[test]
    fn process_exit_releases_server_directory_lock_without_cleanup() {
        const CHILD: &str = "BRAIDPATH_LOCK_TEST_DIR";
        if let Some(dir) = std::env::var_os(CHILD) {
            let _state = open_server(Path::new(&dir), &node(), None, false).unwrap();
            // Skip all destructors, as a service crash would.
            std::process::exit(0);
        }
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("node");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "runtime::mesh::storage::tests::process_exit_releases_server_directory_lock_without_cleanup"])
            .env(CHILD, &dir).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(open_server(&dir, &node(), None, false).is_ok());
    }
}
