//! Durable file operations (PROTOCOL §9.1, THREAT_MODEL N7).

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};

/// `dest` joined with a `/`-separated relative path, refusing anything that could leave `dest`.
pub fn resolve(dest: &Path, rel: &str) -> io::Result<PathBuf> {
    let mut p = dest.to_path_buf();
    for part in rel.split('/') {
        let c = Path::new(part).components().collect::<Vec<_>>();
        if part.is_empty() || c.len() != 1 || !matches!(c[0], Component::Normal(_)) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unsafe path component {part:?}")));
        }
        p.push(part);
    }
    Ok(p)
}

/// Create `rel_dir` under `dest` one component at a time, fsyncing each parent after a creation,
/// so a new directory survives a power loss together with the files in it.
pub fn ensure_dir(dest: &Path, rel_dir: &str) -> io::Result<PathBuf> {
    let mut p = dest.to_path_buf();
    for part in rel_dir.split('/') {
        let parent = p.clone();
        p = resolve(&p, part)?;
        match fs::symlink_metadata(&p) {
            Ok(m) if m.is_dir() => continue,
            Ok(_) => return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{} is not a directory", p.display()))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                match fs::create_dir(&p) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
                fsync_dir(&parent)?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(p)
}

fn no_follow(opts: &mut OpenOptions) {
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(opts, libc::O_NOFOLLOW);
    #[cfg(windows)]
    {
        // FILE_FLAG_OPEN_REPARSE_POINT: open a reparse point itself instead of following it.
        std::os::windows::fs::OpenOptionsExt::custom_flags(opts, 0x0020_0000);
    }
    let _ = opts;
}

/// A fresh `.part` file; fails if anything (file, symlink) already exists at that path.
pub fn create_part(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    no_follow(&mut o);
    o.open(path)
}

/// An existing `.part` file for resuming, never following a symlink.
pub fn open_part(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true).write(true);
    no_follow(&mut o);
    let f = o.open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    Ok(f)
}

/// Remove a file if it exists.
pub fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

pub fn fsync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        // Windows: MOVEFILE_WRITE_THROUGH makes the rename itself durable.
        let _ = dir;
        Ok(())
    }
}

/// Atomically replace `to` with `from` (an existing final is replaced in one step: never a
/// moment without a file at `to`).
pub fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH};
        let wide = |p: &Path| p.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<u16>>();
        let (f, t) = (wide(from), wide(to));
        // SAFETY: both buffers are NUL-terminated UTF-16 paths that outlive the call.
        let ok = unsafe { MoveFileExW(f.as_ptr(), t.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }
    #[cfg(not(windows))]
    {
        fs::rename(from, to)
    }
}
