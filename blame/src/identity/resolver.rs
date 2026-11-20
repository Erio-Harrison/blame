//! cgroup id -> the name a person would recognise, kept up to date.

use std::{collections::HashMap, path::Path};

use blame_common::CgroupMkdirEvent;

use super::docker;
use crate::cgroupfs::{self, CGROUP_ROOT};

/// Hierarchy id of cgroup v2, as in the `0::` line of `/proc/<pid>/cgroup`.
const V2_HIERARCHY: i32 = 0;

/// cgroup id -> label. Paths already seen are kept: a cgroup removed since
/// still has samples that need its name. Ids are never reused on 64-bit
/// kernels, so a kept path cannot end up naming a different cgroup.
pub struct Resolver {
    paths: HashMap<u64, String>,
    names: HashMap<String, String>,
    /// Paths taken from creation events rather than a scan.
    pub learned: u64,
}

impl Resolver {
    pub fn new() -> Self {
        Self {
            paths: HashMap::new(),
            names: HashMap::new(),
            learned: 0,
        }
    }

    /// Record a cgroup from its creation event. A truncated path is left for
    /// the cgroupfs scan to fill in.
    pub fn learn(&mut self, event: &CgroupMkdirEvent) {
        if event.root != V2_HIERARCHY || event.path_truncated() {
            return;
        }
        let path = String::from_utf8_lossy(event.path_bytes()).into_owned();
        if super::docker_container(&path).is_some_and(|id| !self.names.contains_key(&id)) {
            self.refresh_names();
        }
        self.paths.insert(event.id, path);
        self.learned += 1;
    }

    fn refresh_names(&mut self) {
        match docker::container_names() {
            Ok(names) => self.names.extend(names),
            Err(e) => log::debug!("container names unavailable: {e:#}"),
        }
    }

    pub fn refresh(&mut self) {
        self.paths.extend(cgroupfs::scan(Path::new(CGROUP_ROOT)));
        self.refresh_names();
    }

    pub fn label(&mut self, id: u64) -> String {
        if id == 0 {
            return super::UNATTRIBUTED.to_string();
        }
        if !self.paths.contains_key(&id) {
            self.refresh();
        }
        match self.paths.get(&id) {
            Some(path) => super::label(path, &self.names),
            None => format!("cgroup:{id}"),
        }
    }
}
