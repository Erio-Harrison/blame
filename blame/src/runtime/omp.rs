//! OpenMP teams, user side: where a process's GNU OpenMP runtime (libgomp)
//! opens parallel regions, and where in a file an address of the process is.
//! The kernel side is `bpf/runtime/omp.h`.
//!
//! libgomp is a shared library of its own, often one a package brings along
//! (PyTorch's wheels do), so it is looked for in the process's mappings, not
//! in its executable. The functions that open a region are exported: they
//! are there in a stripped library too.

use std::path::Path;

use super::elf::Elf;

/// One line of `/proc/<pid>/maps` that maps a file.
pub(crate) struct Mapping<'a> {
    start: u64,
    end: u64,
    /// Where in the file `start` is.
    offset: u64,
    pub(crate) path: &'a str,
}

pub(crate) fn mappings(maps: &str) -> impl Iterator<Item = Mapping<'_>> {
    maps.lines().filter_map(|line| {
        let mut fields = line.splitn(6, ' ');
        let (start, end) = fields.next()?.split_once('-')?;
        let _perms = fields.next()?;
        let offset = fields.next()?;
        let _dev = fields.next()?;
        let _inode = fields.next()?;
        let path = fields.next()?.trim_start();
        path.starts_with('/').then_some(Mapping {
            start: u64::from_str_radix(start, 16).ok()?,
            end: u64::from_str_radix(end, 16).ok()?,
            offset: u64::from_str_radix(offset, 16).ok()?,
            path: path.strip_suffix(" (deleted)").unwrap_or(path),
        })
    })
}

/// The file a path of a process's mappings names, reached through the
/// process's root: it may live in another mount namespace.
pub fn file_of(proc: &Path, pid: u32, path: &str) -> String {
    format!("{}/{pid}/root{path}", proc.display())
}

fn is_libgomp(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|name| name.starts_with("libgomp") && name.contains(".so"))
}

/// Whether a function libgomp exports opens a parallel region and returns
/// when the region is over, taking the region's function and what it shares
/// as its first two arguments: `GOMP_parallel` and the forms that open a
/// region with a loop, sections or reductions in it. Not the older
/// `GOMP_parallel_start` family, which returns at once and leaves the
/// region open until `GOMP_parallel_end`.
fn opens_a_region(name: &[u8]) -> bool {
    name.starts_with(b"GOMP_parallel") && !name.ends_with(b"_start") && name != b"GOMP_parallel_end"
}

/// A process's libgomp: the path it is mapped from, and where in that file
/// the functions that open regions are.
#[derive(Debug, PartialEq, Eq)]
pub struct Libgomp {
    pub path: String,
    pub entries: Vec<u64>,
}

fn libgomp_in(maps: &str, read: impl Fn(&str) -> Option<Vec<u8>>) -> Option<Libgomp> {
    let path = mappings(maps)
        .map(|m| m.path)
        .find(|path| is_libgomp(path))?;
    let image = read(path)?;
    let elf = Elf::parse(&image)?;
    let entries: Vec<u64> = elf
        .exported_functions_where(opens_a_region)
        .into_iter()
        .filter_map(|addr| elf.file_offset(addr))
        .collect();
    (!entries.is_empty()).then(|| Libgomp {
        path: path.to_owned(),
        entries,
    })
}

/// The libgomp `pid` has loaded, if any.
pub fn libgomp(proc: &Path, pid: u32) -> Option<Libgomp> {
    let maps = std::fs::read_to_string(proc.join(pid.to_string()).join("maps")).ok()?;
    libgomp_in(&maps, |path| std::fs::read(file_of(proc, pid, path)).ok())
}

fn locate_in(maps: &str, addr: u64) -> Option<(String, u64)> {
    mappings(maps)
        .find(|m| addr >= m.start && addr < m.end)
        .map(|m| (m.path.to_owned(), addr - m.start + m.offset))
}

/// The file and the offset in it of the code at `addr` in `pid`: what a
/// probe on a function known only by its address is attached by.
pub fn locate(proc: &Path, pid: u32, addr: u64) -> Option<(String, u64)> {
    let maps = std::fs::read_to_string(proc.join(pid.to_string()).join("maps")).ok()?;
    locate_in(&maps, addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPS: &str = "\
aaaac0a40000-aaaac0d1f000 r-xp 00000000 fd:01 1234                       /usr/bin/python3.12
ffff8c000000-ffff8c021000 rw-p 00000000 00:00 0 
ffff9a2e0000-ffff9a330000 r-xp 00010000 fd:01 5678                       /opt/venv/lib/python3.12/site-packages/torch/lib/libgomp.so.1
ffff9a400000-ffff9a500000 r-xp 00200000 fd:01 9999                       /opt/venv/lib/libtorch_cpu.so (deleted)
ffffd5a00000-ffffd5a21000 rw-p 00000000 00:00 0                          [stack]
";

    #[test]
    fn an_address_is_found_in_the_file_it_is_mapped_from() {
        assert_eq!(
            locate_in(MAPS, 0xffff_9a40_1234),
            Some(("/opt/venv/lib/libtorch_cpu.so".to_owned(), 0x20_1234))
        );
        assert_eq!(
            locate_in(MAPS, 0xaaaa_c0a4_0010),
            Some(("/usr/bin/python3.12".to_owned(), 0x10))
        );
        // Memory that maps no file: the heap, the stack.
        assert_eq!(locate_in(MAPS, 0xffff_8c00_0100), None);
        assert_eq!(locate_in(MAPS, 0xffff_d5a0_0100), None);
        assert_eq!(locate_in(MAPS, 0x1000), None);
    }

    #[test]
    fn libgomp_is_told_by_its_file_name() {
        assert!(is_libgomp("/usr/lib/aarch64-linux-gnu/libgomp.so.1"));
        assert!(is_libgomp("/x/torch.libs/libgomp-a34b3233.so.1.0.0"));
        assert!(!is_libgomp("/usr/lib/libomp.so.5"));
        assert!(!is_libgomp("/usr/lib/libgomp-plugin-nvptx.txt"));
        assert!(!is_libgomp("/opt/libgomp.so.1/python3"));
    }

    #[test]
    fn only_the_functions_that_return_when_the_region_is_over_are_taken() {
        for name in [
            &b"GOMP_parallel"[..],
            b"GOMP_parallel_loop_dynamic",
            b"GOMP_parallel_loop_nonmonotonic_guided",
            b"GOMP_parallel_sections",
            b"GOMP_parallel_reductions",
        ] {
            assert!(opens_a_region(name), "{}", String::from_utf8_lossy(name));
        }
        for name in [
            &b"GOMP_parallel_start"[..],
            b"GOMP_parallel_end",
            b"GOMP_parallel_loop_dynamic_start",
            b"GOMP_parallel_sections_start",
            b"GOMP_barrier",
            b"omp_get_thread_num",
        ] {
            assert!(!opens_a_region(name), "{}", String::from_utf8_lossy(name));
        }
    }

    #[test]
    fn a_process_without_libgomp_has_none() {
        let maps = "aaaac0a40000-aaaac0d1f000 r-xp 00000000 fd:01 1234 /usr/bin/python3.12\n";
        assert_eq!(libgomp_in(maps, |_| panic!("nothing to read")), None);
        // The library is there but cannot be read, or is not what it is named.
        assert_eq!(libgomp_in(MAPS, |_| None), None);
        assert_eq!(libgomp_in(MAPS, |_| Some(b"not ELF".to_vec())), None);
    }

    #[test]
    fn this_machines_libgomp_has_the_entries() {
        // Where the distributions put it; skipped where there is none.
        let Some(path) = [
            "/usr/lib/aarch64-linux-gnu/libgomp.so.1",
            "/usr/lib/x86_64-linux-gnu/libgomp.so.1",
            "/usr/lib64/libgomp.so.1",
        ]
        .into_iter()
        .find(|path| Path::new(path).exists()) else {
            return;
        };
        let maps = format!("ffff9a2e0000-ffff9a330000 r-xp 00000000 fd:01 5678    {path}\n");
        let found = libgomp_in(&maps, |path| std::fs::read(path).ok()).expect("libgomp");
        assert_eq!(found.path, path);
        // GOMP_parallel and a handful of loop forms at least.
        assert!(found.entries.len() >= 5, "{:?}", found.entries);
    }
}
