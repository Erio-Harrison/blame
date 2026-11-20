//! Classify a cgroup path (relative to the cgroupfs root) into what created it.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runtime {
    Docker,
    Containerd,
    CriO,
    /// The path carries a bare container id with no runtime marker.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qos {
    Guaranteed,
    Burstable,
    BestEffort,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRef {
    pub runtime: Runtime,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CgroupKind {
    Systemd {
        unit: String,
    },
    Container(ContainerRef),
    Pod {
        uid: String,
        qos: Qos,
        container: Option<ContainerRef>,
    },
    Unknown,
}

const RUNTIME_PREFIXES: [(&str, Runtime); 3] = [
    ("docker-", Runtime::Docker),
    ("cri-containerd-", Runtime::Containerd),
    ("crio-", Runtime::CriO),
];

pub fn classify(path: &str) -> CgroupKind {
    let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    if let Some(i) = comps
        .iter()
        .position(|c| *c == "kubepods" || *c == "kubepods.slice")
    {
        return classify_pod(&comps[i + 1..]);
    }
    let Some(&leaf) = comps.last() else {
        return CgroupKind::Unknown;
    };
    if let Some(container) = scope_container(leaf) {
        return CgroupKind::Container(container);
    }
    if comps.len() >= 2 && comps[comps.len() - 2] == "docker" && is_container_id(leaf) {
        return CgroupKind::Container(ContainerRef {
            runtime: Runtime::Docker,
            id: leaf.to_string(),
        });
    }
    let is_unit = [".service", ".scope", ".slice"]
        .iter()
        .any(|suffix| leaf.ends_with(suffix));
    let is_runtime_scope = RUNTIME_PREFIXES.iter().any(|(p, _)| leaf.starts_with(p));
    if is_unit && !is_runtime_scope {
        return CgroupKind::Systemd {
            unit: leaf.to_string(),
        };
    }
    CgroupKind::Unknown
}

/// Components below the kubepods root: optional QoS level, the pod, then the container.
fn classify_pod(rest: &[&str]) -> CgroupKind {
    let mut qos = Qos::Guaranteed;
    let mut uid = None;
    let mut container = None;
    for comp in rest {
        let name = comp.strip_suffix(".slice").unwrap_or(comp);
        if let Some(c) = scope_container(comp) {
            container = Some(c);
        } else if is_container_id(comp) {
            container = Some(ContainerRef {
                runtime: Runtime::Unknown,
                id: comp.to_string(),
            });
        } else if let Some((q, u)) = parse_pod_component(name) {
            if let Some(q) = q {
                qos = q;
            }
            uid = Some(u);
        } else if let Some(q) = parse_qos(name) {
            qos = q;
        }
    }
    match uid {
        Some(uid) => CgroupKind::Pod {
            uid,
            qos,
            container,
        },
        None => CgroupKind::Unknown,
    }
}

fn parse_qos(name: &str) -> Option<Qos> {
    match name.strip_prefix("kubepods-").unwrap_or(name) {
        "besteffort" => Some(Qos::BestEffort),
        "burstable" => Some(Qos::Burstable),
        _ => None,
    }
}

/// `pod<uid>`, `kubepods-pod<uid>` or `kubepods-<qos>-pod<uid>`; systemd writes the uid with `_`.
fn parse_pod_component(name: &str) -> Option<(Option<Qos>, String)> {
    let (qos, uid) = if let Some(uid) = name.strip_prefix("kubepods-pod") {
        (None, uid)
    } else if let Some(rest) = name.strip_prefix("kubepods-") {
        let (q, uid) = rest.split_once("-pod")?;
        (Some(parse_qos(q)?), uid)
    } else {
        (None, name.strip_prefix("pod")?)
    };
    let uid = uid.replace('_', "-");
    is_pod_uid(&uid).then_some((qos, uid))
}

fn scope_container(comp: &str) -> Option<ContainerRef> {
    let name = comp.strip_suffix(".scope")?;
    RUNTIME_PREFIXES.iter().find_map(|(prefix, runtime)| {
        let id = name.strip_prefix(prefix)?;
        is_container_id(id).then(|| ContainerRef {
            runtime: *runtime,
            id: id.to_string(),
        })
    })
}

fn is_container_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_pod_uid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID_A: &str = "1fabe94538267159e623c3cf32b1e1a32a9e51274b73beceacf35d7f23381ecf";
    const ID_B: &str = "fff1d5e8c6888bbadc191219d39d62b697db46538bf925e635ed5eabf63f972b";
    const POD: &str = "8c0c6aa7-0a60-4ce4-b1e9-6af0b8b40ecc";

    fn container(runtime: Runtime, id: &str) -> ContainerRef {
        ContainerRef {
            runtime,
            id: id.to_string(),
        }
    }

    fn unit(name: &str) -> CgroupKind {
        CgroupKind::Systemd {
            unit: name.to_string(),
        }
    }

    #[test]
    fn systemd_service() {
        assert_eq!(classify("/system.slice/ssh.service"), unit("ssh.service"));
    }

    #[test]
    fn systemd_session_scope() {
        assert_eq!(
            classify("/user.slice/user-1000.slice/session-4.scope"),
            unit("session-4.scope")
        );
    }

    #[test]
    fn systemd_user_service_takes_leaf_unit() {
        assert_eq!(
            classify("/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service"),
            unit("foo.service")
        );
    }

    #[test]
    fn systemd_template_instance() {
        assert_eq!(
            classify("/system.slice/system-getty.slice/getty@tty1.service"),
            unit("getty@tty1.service")
        );
    }

    // Captured from Docker 29.1.3 with the systemd cgroup driver.
    #[test]
    fn docker_systemd_driver() {
        assert_eq!(
            classify(&format!("/system.slice/docker-{ID_A}.scope")),
            CgroupKind::Container(container(Runtime::Docker, ID_A))
        );
    }

    #[test]
    fn docker_cgroupfs_driver() {
        assert_eq!(
            classify(&format!("/docker/{ID_A}")),
            CgroupKind::Container(container(Runtime::Docker, ID_A))
        );
    }

    // Captured from k3s v1.34.13 (containerd, systemd cgroup driver).
    #[test]
    fn k8s_besteffort_containerd() {
        let path = format!(
            "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8c0c6aa7_0a60_4ce4_b1e9_6af0b8b40ecc.slice/cri-containerd-{ID_B}.scope"
        );
        assert_eq!(
            classify(&path),
            CgroupKind::Pod {
                uid: POD.to_string(),
                qos: Qos::BestEffort,
                container: Some(container(Runtime::Containerd, ID_B)),
            }
        );
    }

    #[test]
    fn k8s_burstable_crio() {
        let path = format!(
            "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod8c0c6aa7_0a60_4ce4_b1e9_6af0b8b40ecc.slice/crio-{ID_B}.scope"
        );
        assert_eq!(
            classify(&path),
            CgroupKind::Pod {
                uid: POD.to_string(),
                qos: Qos::Burstable,
                container: Some(container(Runtime::CriO, ID_B)),
            }
        );
    }

    // Guaranteed pods sit directly under kubepods.slice, with no QoS slice.
    #[test]
    fn k8s_guaranteed_has_no_qos_slice() {
        let path = format!(
            "/kubepods.slice/kubepods-pod8c0c6aa7_0a60_4ce4_b1e9_6af0b8b40ecc.slice/cri-containerd-{ID_B}.scope"
        );
        assert_eq!(
            classify(&path),
            CgroupKind::Pod {
                uid: POD.to_string(),
                qos: Qos::Guaranteed,
                container: Some(container(Runtime::Containerd, ID_B)),
            }
        );
    }

    // The pod-level cgroup itself (processes attached directly, e.g. the pause container's parent).
    #[test]
    fn k8s_pod_level_cgroup_has_no_container() {
        let path = "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8c0c6aa7_0a60_4ce4_b1e9_6af0b8b40ecc.slice";
        assert_eq!(
            classify(path),
            CgroupKind::Pod {
                uid: POD.to_string(),
                qos: Qos::BestEffort,
                container: None,
            }
        );
    }

    #[test]
    fn k8s_cgroupfs_driver() {
        let path = format!("/kubepods/burstable/pod{POD}/{ID_B}");
        assert_eq!(
            classify(&path),
            CgroupKind::Pod {
                uid: POD.to_string(),
                qos: Qos::Burstable,
                container: Some(container(Runtime::Unknown, ID_B)),
            }
        );
    }

    // Inferred, not captured: a node that is itself a container prefixes the
    // pod path with the node container's own cgroup.
    #[test]
    fn k8s_nested_in_node_container() {
        let path = format!(
            "/docker/{ID_A}/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8c0c6aa7_0a60_4ce4_b1e9_6af0b8b40ecc.slice/cri-containerd-{ID_B}.scope"
        );
        assert_eq!(
            classify(&path),
            CgroupKind::Pod {
                uid: POD.to_string(),
                qos: Qos::BestEffort,
                container: Some(container(Runtime::Containerd, ID_B)),
            }
        );
    }

    #[test]
    fn unrecognized_paths_are_unknown() {
        for p in [
            "",
            "/",
            "/foo/bar",
            "/system.slice/docker-nothex.scope",
            "/docker/short",
        ] {
            assert_eq!(classify(p), CgroupKind::Unknown, "{p}");
        }
    }
}
