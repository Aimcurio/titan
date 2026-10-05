//! Disposable real SQLite adapter. Only fixed F07 fixture paths are addressable.
//! Imported dependency rows are the current synthetic state, not live operational data.
use crate::{
    eligibility::FixturePromotionEligibilityV1,
    evidence::hash,
    transition::{
        F07Error, F07Result, FixtureDependencySnapshotV1, FixtureTransitionReceiptV1, decode,
        eligibility_record, encode, environment, validate_receipt,
    },
    verification::ExpectedPriorCanonicalV1,
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
pub const F07_ROOT: &str =
    r"C:\Users\15103\Documents\Codex\2026-09-29\files-pasted-by-the-user-titan\work\f07-fixtures";

pub(crate) fn basis_digest(eligibility: &[u8], snapshot: &[u8]) -> String {
    // Length framing prevents concatenation ambiguity.
    let mut bytes = (eligibility.len() as u64).to_le_bytes().to_vec();
    bytes.extend_from_slice(eligibility);
    bytes.extend_from_slice(&(snapshot.len() as u64).to_le_bytes());
    bytes.extend_from_slice(snapshot);
    hash(b"TITAN-FWD-F07\0import-v1\0", &bytes)
}
const TABLES: [(&str, &str); 5] = [
    (
        "basis",
        "CREATE TABLE basis(eligibility_id TEXT PRIMARY KEY NOT NULL,eligibility BLOB NOT NULL,snapshot BLOB NOT NULL,digest TEXT NOT NULL)",
    ),
    (
        "dependencies",
        "CREATE TABLE dependencies(name TEXT PRIMARY KEY NOT NULL,value BLOB NOT NULL)",
    ),
    (
        "pointer",
        "CREATE TABLE pointer(singleton INTEGER PRIMARY KEY CHECK(singleton=1),value BLOB NOT NULL)",
    ),
    (
        "consumed",
        "CREATE TABLE consumed(eligibility_id TEXT PRIMARY KEY NOT NULL REFERENCES basis(eligibility_id),transition_id TEXT NOT NULL UNIQUE)",
    ),
    (
        "receipts",
        "CREATE TABLE receipts(transition_id TEXT PRIMARY KEY NOT NULL,eligibility_id TEXT NOT NULL UNIQUE REFERENCES consumed(eligibility_id),receipt BLOB NOT NULL)",
    ),
];
pub(crate) fn validate_schema(connection: &Connection) -> F07Result<()> {
    let mut expected = std::collections::BTreeMap::new();
    for (name, sql) in TABLES {
        expected.insert(
            name.to_string(),
            ("table".to_string(), name.to_string(), Some(sql.to_string())),
        );
    }
    for (table, number) in [
        ("basis", 1),
        ("dependencies", 1),
        ("consumed", 1),
        ("consumed", 2),
        ("receipts", 1),
        ("receipts", 2),
    ] {
        expected.insert(
            format!("sqlite_autoindex_{table}_{number}"),
            ("index".to_string(), table.to_string(), None),
        );
    }
    let mut statement = connection
        .prepare("SELECT name,type,tbl_name,sql FROM sqlite_schema ORDER BY name")
        .map_err(environment)?;
    let mut observed = std::collections::BTreeMap::new();
    for row in statement
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(environment)?
    {
        let (name, kind, table, sql) = row.map_err(environment)?;
        observed.insert(name, (kind, table, sql));
    }
    if observed != expected {
        return Err(F07Error::BlockedIntegrity);
    }
    Ok(())
}
fn ordinary(path: &Path) -> F07Result<()> {
    for component in path.ancestors() {
        if !component.exists() {
            continue;
        }
        let metadata = fs::symlink_metadata(component).map_err(|_| F07Error::BlockedEnvironment)?;
        let mut link = metadata.file_type().is_symlink();
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            link |= metadata.file_attributes() & 0x400 != 0;
        }
        if link {
            return Err(F07Error::BlockedEnvironment);
        }
    }
    Ok(())
}
fn case_path(case: &str) -> F07Result<PathBuf> {
    if case.is_empty()
        || case.len() > 64
        || !case
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(F07Error::BlockedEnvironment);
    }
    Ok(Path::new(F07_ROOT).join(case).join("transition.sqlite"))
}
#[cfg(windows)]
fn file_identity(path: &Path) -> F07Result<(u64, u64)> {
    use std::{mem::MaybeUninit, os::windows::io::AsRawHandle};
    #[repr(C)]
    struct Time {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    struct Info {
        attributes: u32,
        creation: Time,
        access: Time,
        write: Time,
        volume: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(handle: *mut std::ffi::c_void, info: *mut Info) -> i32;
    }
    let file = fs::File::open(path).map_err(|_| F07Error::BlockedEnvironment)?;
    let mut info = MaybeUninit::<Info>::uninit();
    // The OS fills exactly the documented repr(C) handle-information structure.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
        return Err(F07Error::BlockedEnvironment);
    }
    let info = unsafe { info.assume_init() };
    if info.links != 1 {
        return Err(F07Error::BlockedEnvironment);
    }
    Ok((
        u64::from(info.volume),
        (u64::from(info.index_high) << 32) | u64::from(info.index_low),
    ))
}
#[cfg(not(windows))]
fn file_identity(path: &Path) -> F07Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(path).map_err(|_| F07Error::BlockedEnvironment)?;
    if metadata.nlink() != 1 {
        return Err(F07Error::BlockedEnvironment);
    }
    Ok((metadata.dev(), metadata.ino()))
}
fn connect(path: &Path) -> F07Result<Connection> {
    ordinary(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| F07Error::BlockedEnvironment)?;
    if !metadata.is_file() {
        return Err(F07Error::BlockedEnvironment);
    }
    let canonical = fs::canonicalize(path).map_err(|_| F07Error::BlockedEnvironment)?;
    if !canonical.starts_with(fs::canonicalize(F07_ROOT).map_err(|_| F07Error::BlockedEnvironment)?)
    {
        return Err(F07Error::BlockedEnvironment);
    }
    file_identity(path)?;
    let journal = path.with_extension("sqlite-journal");
    if journal.exists() {
        ordinary(&journal)?;
        file_identity(&journal)?;
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(environment)?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(environment)?;
    connection.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;").map_err(environment)?;
    let journal: String = connection
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .map_err(environment)?;
    let sync: i64 = connection
        .query_row("PRAGMA synchronous", [], |r| r.get(0))
        .map_err(environment)?;
    let foreign: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .map_err(environment)?;
    let trusted: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |r| r.get(0))
        .map_err(environment)?;
    if journal != "delete" || sync != 2 || foreign != 1 || trusted != 0 {
        return Err(F07Error::BlockedEnvironment);
    }
    Ok(connection)
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct FixtureStoreStateV1 {
    pub pointer: ExpectedPriorCanonicalV1,
    pub receipts: Vec<FixtureTransitionReceiptV1>,
    pub consumed: Vec<(String, String)>,
}
pub struct FixtureTransitionStoreV1 {
    path: PathBuf,
    identity: (u64, u64),
    pub(crate) connection: Connection,
}
impl FixtureTransitionStoreV1 {
    /// Imports a previously validated genuine F06 object and an independently
    /// captured current snapshot into a NEW disposable store. It cannot replace
    /// an existing pointer, consumed eligibility, or receipt.
    pub fn create(
        case: &str,
        eligibility: &FixturePromotionEligibilityV1,
        snapshot: &FixtureDependencySnapshotV1,
    ) -> F07Result<Self> {
        let record = eligibility_record(eligibility.canonical_bytes())?;
        snapshot.matches(&record)?;
        let path = case_path(case)?;
        ordinary(&path)?;
        let parent = path.parent().ok_or(F07Error::BlockedEnvironment)?;
        fs::create_dir_all(parent).map_err(|_| F07Error::BlockedEnvironment)?;
        ordinary(parent)?;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| F07Error::BlockedEnvironment)?;
        let mut connection = connect(&path)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(environment)?;
        for (_, sql) in TABLES {
            tx.execute_batch(sql).map_err(environment)?;
        }
        validate_schema(&tx)?;
        let snapshot_bytes = encode(snapshot)?;
        tx.execute(
            "INSERT INTO basis VALUES(?1,?2,?3,?4)",
            params![
                eligibility.record_id(),
                eligibility.canonical_bytes(),
                snapshot_bytes,
                basis_digest(eligibility.canonical_bytes(), &snapshot_bytes)
            ],
        )
        .map_err(environment)?;
        for (name, value) in &snapshot.rows {
            tx.execute(
                "INSERT INTO dependencies VALUES(?1,?2)",
                params![name, value],
            )
            .map_err(environment)?;
        }
        let request =
            crate::transition::FixtureTransitionRequestV1::from_eligibility("import", eligibility)?;
        tx.execute(
            "INSERT INTO pointer VALUES(1,?1)",
            [encode(&request.expected_prior)?],
        )
        .map_err(environment)?;
        tx.commit().map_err(environment)?;
        let identity = file_identity(&path)?;
        Ok(Self {
            path,
            identity,
            connection,
        })
    }
    pub fn open(case: &str) -> F07Result<Self> {
        let path = case_path(case)?;
        let connection = connect(&path)?;
        let identity = file_identity(&path)?;
        Ok(Self {
            path,
            identity,
            connection,
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn check_path(&self) -> F07Result<()> {
        ordinary(&self.path)?;
        if file_identity(&self.path)? != self.identity
            || !fs::canonicalize(&self.path)
                .map_err(|_| F07Error::BlockedEnvironment)?
                .starts_with(fs::canonicalize(F07_ROOT).map_err(|_| F07Error::BlockedEnvironment)?)
        {
            return Err(F07Error::BlockedEnvironment);
        }
        Ok(())
    }
    pub fn dependency_names(&self) -> F07Result<Vec<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT name FROM dependencies ORDER BY name")
            .map_err(environment)?;
        statement
            .query_map([], |r| r.get(0))
            .map_err(environment)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(environment)
    }
    pub fn dependency(&self, name: &str) -> F07Result<Vec<u8>> {
        self.connection
            .query_row(
                "SELECT value FROM dependencies WHERE name=?1",
                [name],
                |r| r.get(0),
            )
            .map_err(environment)
    }
    /// Test-only externally supplied state drift. No transition calls this method.
    pub fn set_dependency(&mut self, name: &str, value: &[u8]) -> F07Result<()> {
        self.check_path()?;
        if self
            .connection
            .execute(
                "UPDATE dependencies SET value=?1 WHERE name=?2",
                params![value, name],
            )
            .map_err(environment)?
            != 1
        {
            return Err(F07Error::BlockedEnvironment);
        }
        Ok(())
    }
    pub fn remove_dependency(&mut self, name: &str) -> F07Result<()> {
        self.check_path()?;
        self.connection
            .execute("DELETE FROM dependencies WHERE name=?1", [name])
            .map_err(environment)?;
        Ok(())
    }
    pub fn state(&self) -> F07Result<FixtureStoreStateV1> {
        self.check_path()?;
        // A single read transaction prevents mixed pre/post-commit inspection.
        let read = self
            .connection
            .unchecked_transaction()
            .map_err(environment)?;
        let bytes: Vec<u8> = read
            .query_row("SELECT value FROM pointer WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .map_err(environment)?;
        let pointer = decode(&bytes)?;
        let mut statement = read
            .prepare("SELECT receipt FROM receipts ORDER BY transition_id")
            .map_err(environment)?;
        let mut receipts = Vec::new();
        for row in statement
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map_err(environment)?
        {
            receipts.push(validate_receipt(&row.map_err(environment)?)?);
        }
        let mut statement = read
            .prepare("SELECT eligibility_id,transition_id FROM consumed ORDER BY eligibility_id")
            .map_err(environment)?;
        let consumed = statement
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(environment)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(environment)?;
        Ok(FixtureStoreStateV1 {
            pointer,
            receipts,
            consumed,
        })
    }
}
