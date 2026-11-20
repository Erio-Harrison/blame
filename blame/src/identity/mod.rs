//! Turn a cgroup path into the name a person would recognise.

mod classify;
pub mod docker;
mod resolver;

use std::collections::HashMap;

use classify::{CgroupKind, ContainerRef, Runtime, classify};
pub use resolver::Resolver;

pub const UNATTRIBUTED: &str = "(unattributed)";

pub fn label(path: &str, names: &HashMap<String, String>) -> String {
    match classify(path) {
        CgroupKind::Systemd { unit } => unit,
        CgroupKind::Container(container) => container_label(&container, names),
        CgroupKind::Pod {
            uid,
            container: None,
            ..
        } => format!("pod:{}", short(&uid, 8)),
        CgroupKind::Pod {
            uid,
            container: Some(container),
            ..
        } => format!("pod:{}/{}", short(&uid, 8), short(&container.id, 12)),
        CgroupKind::Unknown => path.to_string(),
    }
}

/// The Docker container id a path belongs to, if any. Its name has to be
/// asked for while the container exists.
pub fn docker_container(path: &str) -> Option<String> {
    match classify(path) {
        CgroupKind::Container(c) if c.runtime == Runtime::Docker => Some(c.id),
        _ => None,
    }
}

fn container_label(container: &ContainerRef, names: &HashMap<String, String>) -> String {
    let runtime = match container.runtime {
        Runtime::Docker => "docker",
        Runtime::Containerd => "containerd",
        Runtime::CriO => "crio",
        Runtime::Unknown => "container",
    };
    match names.get(&container.id) {
        Some(name) => format!("{runtime}:{name}"),
        None => format!("{runtime}:{}", short(&container.id, 12)),
    }
}

fn short(s: &str, n: usize) -> &str {
    s.get(..n).unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "1fabe94538267159e623c3cf32b1e1a32a9e51274b73beceacf35d7f23381ecf";

    #[test]
    fn systemd_unit_is_its_own_label() {
        assert_eq!(
            label("/system.slice/ssh.service", &HashMap::new()),
            "ssh.service"
        );
    }

    #[test]
    fn docker_container_uses_the_name_when_known() {
        let names = HashMap::from([(ID.to_string(), "nw-test".to_string())]);
        let path = format!("/system.slice/docker-{ID}.scope");
        assert_eq!(label(&path, &names), "docker:nw-test");
        assert_eq!(label(&path, &HashMap::new()), "docker:1fabe9453826");
    }

    #[test]
    fn pod_container_shows_short_uid_and_container() {
        let path = format!(
            "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8c0c6aa7_0a60_4ce4_b1e9_6af0b8b40ecc.slice/cri-containerd-{ID}.scope"
        );
        assert_eq!(label(&path, &HashMap::new()), "pod:8c0c6aa7/1fabe9453826");
    }

    #[test]
    fn docker_container_id_only_for_docker_paths() {
        let path = format!("/system.slice/docker-{ID}.scope");
        assert_eq!(docker_container(&path).as_deref(), Some(ID));
        assert_eq!(docker_container("/system.slice/ssh.service"), None);
        let pod = format!("/kubepods.slice/kubepods-pod1.slice/cri-containerd-{ID}.scope");
        assert_eq!(docker_container(&pod), None);
    }

    #[test]
    fn unknown_path_is_shown_as_is() {
        assert_eq!(label("/foo/bar", &HashMap::new()), "/foo/bar");
    }
}
