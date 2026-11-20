//! The eBPF object, plus the few kernel interfaces libbpf-rs does not wrap.

use std::{
    ffi::OsStr,
    io,
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd},
    path::PathBuf,
    sync::OnceLock,
};

use anyhow::{Context as _, Result};
use libbpf_rs::{
    MapCore, MapFlags, PrintLevel, RingBuffer, RingBufferBuilder,
    skel::{OpenSkel as _, SkelBuilder as _},
};
use tokio::io::{Interest, unix::AsyncFd};

mod skel {
    include!(concat!(env!("OUT_DIR"), "/blame.skel.rs"));
}

pub type Skel = skel::BlameSkel<'static>;
pub type OpenSkel = skel::OpenBlameSkel<'static>;

/// Route libbpf's own messages (including verifier output on a failed load)
/// through `log`.
pub fn init_logging() {
    libbpf_rs::set_print(Some((PrintLevel::Debug, |level, msg| {
        let msg = msg.trim_end();
        match level {
            PrintLevel::Warn => log::warn!("libbpf: {msg}"),
            PrintLevel::Info => log::info!("libbpf: {msg}"),
            PrintLevel::Debug => log::debug!("libbpf: {msg}"),
        }
    })));
}

static TARGET_BTF: OnceLock<PathBuf> = OnceLock::new();

/// Relocate against this BTF file instead of the running kernel's, for kernels
/// built without BTF.
pub fn set_target_btf(path: PathBuf) {
    let _ = TARGET_BTF.set(path);
}

/// Open the embedded object. The agent opens one object and keeps it until it
/// exits, so the storage the skeleton borrows is simply never freed.
pub fn open() -> Result<OpenSkel> {
    let storage = Box::leak(Box::new(MaybeUninit::uninit()));
    let mut builder = skel::BlameSkelBuilder::default();
    if let Some(path) = TARGET_BTF.get() {
        builder
            .obj_builder
            .btf_custom_path(path)
            .with_context(|| format!("using BTF from {}", path.display()))?;
    }
    let mut open = builder.open(storage).context("opening the eBPF object")?;
    // Outside the initial PID namespace, the kernel side numbers processes
    // as this one does (pidns.h). Left at 0 if it cannot be told.
    if let Some(ns) = crate::procfs::pid_ns(std::path::Path::new("/proc"))
        && !ns.is_initial()
    {
        let rodata = open
            .maps
            .rodata_data
            .as_deref_mut()
            .context("the eBPF object has no read-only data")?;
        rodata.pidns_dev = ns.dev;
        rodata.pidns_ino = ns.ino;
    }
    Ok(open)
}

/// Load only the named programs; the others are left out of the kernel.
pub fn autoload_only(open: &mut OpenSkel, wanted: &[&str]) {
    for mut program in open.open_object_mut().progs_mut() {
        let keep = wanted.iter().any(|name| program.name() == OsStr::new(name));
        program.set_autoload(keep);
    }
}

/// Load the object. CO-RE relocations are resolved against the running
/// kernel's BTF here, so a tracepoint field that is missing or has changed
/// type fails this call rather than being read at the wrong place.
pub fn load(open: OpenSkel) -> Result<Skel> {
    open.load().context(
        "loading the eBPF programs (needs root and kernel BTF; run with RUST_LOG=warn for libbpf's reason)",
    )
}

/// Values of one key of a per-CPU map, one per possible CPU.
fn percpu(map: &dyn MapCore, key: &[u8]) -> Result<Vec<Vec<u8>>> {
    map.lookup_percpu(key, MapFlags::ANY)?
        .context("key not present")
}

fn u64_at(bytes: &[u8], index: usize) -> u64 {
    let start = index * 8;
    u64::from_ne_bytes(bytes[start..start + 8].try_into().expect("8 bytes"))
}

/// Sum over CPUs of slot `index` of a per-CPU array of `u64`.
pub fn percpu_u64_sum(map: &dyn MapCore, index: u32) -> Result<u64> {
    Ok(percpu(map, &index.to_ne_bytes())?
        .iter()
        .map(|cpu| u64_at(cpu, 0))
        .sum())
}

/// Every entry of a per-CPU hash of `u64 -> [u64; N]`, summed over CPUs.
pub fn percpu_hash_u64_arrays<const N: usize>(map: &dyn MapCore) -> Result<Vec<(u64, [u64; N])>> {
    let mut out = Vec::new();
    for key in map.keys() {
        let id = u64_at(&key, 0);
        let mut sum = [0u64; N];
        for cpu in percpu(map, &key)? {
            for (k, slot) in sum.iter_mut().enumerate() {
                *slot += u64_at(&cpu, k);
            }
        }
        out.push((id, sum));
    }
    Ok(out)
}

/// Turn on the kernel's per-program run time accounting. It stays on while the
/// returned fd is open and turns itself off when the process exits; no global
/// sysctl is touched.
pub fn enable_run_time_stats() -> Result<OwnedFd> {
    // SAFETY: plain syscall wrapper, no pointers involved.
    let fd = unsafe { libbpf_sys::bpf_enable_stats(libbpf_sys::BPF_STATS_RUN_TIME) };
    if fd < 0 {
        return Err(io::Error::from_raw_os_error(-fd)).context("enabling BPF run time statistics");
    }
    // SAFETY: the kernel just handed us this fd and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `(calls, total run time in ns)` of a loaded program.
pub fn run_stats(program: &impl AsFd) -> Result<(u64, u64)> {
    let mut info = libbpf_sys::bpf_prog_info::default();
    let mut len = size_of::<libbpf_sys::bpf_prog_info>() as u32;
    // SAFETY: `info` and `len` are valid for writes and `len` is its size.
    let ret = unsafe {
        libbpf_sys::bpf_prog_get_info_by_fd(program.as_fd().as_raw_fd(), &mut info, &mut len)
    };
    if ret < 0 {
        return Err(io::Error::from_raw_os_error(-ret)).context("reading program info");
    }
    Ok((info.run_cnt, info.run_time_ns))
}

/// The `EVENTS` ring buffer, wired into tokio.
pub struct Events {
    ring: RingBuffer<'static>,
    ready: AsyncFd<RawFd>,
}

impl Events {
    /// `handle` is called once per record, from [`Self::wait`] and
    /// [`Self::drain`].
    pub fn new(map: &dyn MapCore, mut handle: impl FnMut(&[u8]) + 'static) -> Result<Self> {
        let mut builder = RingBufferBuilder::new();
        builder
            .add(map, move |record| {
                handle(record);
                0
            })
            .context("adding the EVENTS ring buffer")?;
        let ring = builder
            .build()
            .context("creating the ring buffer consumer")?;
        let ready = AsyncFd::with_interest(ring.epoll_fd(), Interest::READABLE)
            .context("registering the ring buffer for readiness notifications")?;
        Ok(Self { ring, ready })
    }

    /// Wait until records arrive, then consume all of them.
    pub async fn wait(&self) -> Result<()> {
        let mut guard = self.ready.readable().await?;
        // Drain fully before clearing readiness: the notification is
        // edge-triggered, so a partial drain can strand records.
        self.drain()?;
        guard.clear_ready();
        Ok(())
    }

    /// Consume whatever is in the buffer now, without waiting.
    pub fn drain(&self) -> Result<()> {
        self.ring.consume().context("consuming the ring buffer")
    }
}
