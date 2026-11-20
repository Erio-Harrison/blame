//! Map cgroup ids to paths by walking cgroupfs.

use std::{collections::HashMap, fs, os::unix::fs::MetadataExt as _, path::Path};

pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The id the kernel reports for a cgroup is the inode number of its directory.
/// Returns id -> path relative to `root` ("/" for the root itself).
pub fn scan(root: &Path) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    if let Ok(meta) = fs::metadata(root) {
        out.insert(meta.ino(), "/".to_string());
    }
    walk(root, "", &mut out);
    out
}

fn walk(dir: &Path, rel: &str, out: &mut HashMap<u64, String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if !kind.is_dir() {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let path = format!("{rel}/{}", entry.file_name().to_string_lossy());
        out.insert(meta.ino(), path.clone());
        walk(&entry.path(), &path, out);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("blame-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn scan_maps_inode_to_relative_path() {
        let root = tempdir("scan");
        fs::create_dir_all(root.join("system.slice/a.service")).unwrap();
        fs::write(root.join("system.slice/file"), "").unwrap();
        let ids = scan(&root);
        let ino = fs::metadata(root.join("system.slice/a.service"))
            .unwrap()
            .ino();
        assert_eq!(
            ids.get(&ino).map(String::as_str),
            Some("/system.slice/a.service")
        );
        assert_eq!(ids.len(), 3); // root, system.slice, a.service
        fs::remove_dir_all(&root).unwrap();
    }
}
