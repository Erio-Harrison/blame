//! The little of a 64-bit little-endian ELF file that the adapters need:
//! sections by name, symbols, the TLS segment, where an address is in the
//! file.

/// The little of a 64-bit little-endian ELF file that is needed here.
pub(crate) struct Elf<'a> {
    pub image: &'a [u8],
    sections: Vec<Section<'a>>,
    /// Loaded segments: (address, offset in the file, bytes in the file).
    loads: Vec<(u64, u64, u64)>,
    pub tls: Option<TlsSegment>,
    /// `e_machine`: [`EM_AARCH64`], 62 for x86-64, ...
    pub machine: u16,
}

pub(crate) const EM_AARCH64: u16 = 183;

struct Section<'a> {
    name: &'a [u8],
    kind: u32,
    link: u32,
    addr: u64,
    data: &'a [u8],
}

pub(crate) struct TlsSegment {
    pub size: u64,
    pub align: u64,
}

const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;
const SHT_NOBITS: u32 = 8;
const PT_LOAD: u32 = 1;
const PT_TLS: u32 = 7;
const STT_FUNC: u8 = 2;
const STT_TLS: u8 = 6;

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}
fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}
fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

fn c_str(bytes: &[u8], at: usize) -> &[u8] {
    let rest = bytes.get(at..).unwrap_or_default();
    &rest[..rest.iter().position(|b| *b == 0).unwrap_or(rest.len())]
}

impl<'a> Elf<'a> {
    pub fn parse(image: &'a [u8]) -> Option<Self> {
        // 64-bit, little-endian.
        if !image.starts_with(b"\x7fELF") || image.get(4..6)? != [2, 1] {
            return None;
        }
        let ph_off = u64_at(image, 0x20)? as usize;
        let sh_off = u64_at(image, 0x28)? as usize;
        let ph_size = usize::from(u16_at(image, 0x36)?);
        let ph_count = usize::from(u16_at(image, 0x38)?);
        let sh_size = usize::from(u16_at(image, 0x3a)?);
        let sh_count = usize::from(u16_at(image, 0x3c)?);
        let names_index = usize::from(u16_at(image, 0x3e)?);

        let mut tls = None;
        let mut loads = Vec::new();
        for i in 0..ph_count {
            let at = ph_off + i * ph_size;
            if u32_at(image, at)? == PT_LOAD {
                loads.push((
                    u64_at(image, at + 0x10)?,
                    u64_at(image, at + 8)?,
                    u64_at(image, at + 0x20)?,
                ));
            }
            if u32_at(image, at)? == PT_TLS {
                tls = Some(TlsSegment {
                    size: u64_at(image, at + 0x28)?,
                    align: u64_at(image, at + 0x30)?,
                });
            }
        }

        let mut raw = Vec::with_capacity(sh_count);
        for i in 0..sh_count {
            let at = sh_off + i * sh_size;
            let kind = u32_at(image, at + 4)?;
            let offset = u64_at(image, at + 0x18)? as usize;
            let size = u64_at(image, at + 0x20)? as usize;
            let data = if kind == SHT_NOBITS {
                &[][..]
            } else {
                image.get(offset..offset.checked_add(size)?)?
            };
            raw.push((
                u32_at(image, at)?,
                kind,
                u32_at(image, at + 0x28)?,
                u64_at(image, at + 0x10)?,
                data,
            ));
        }
        let names = raw.get(names_index).map_or(&[][..], |section| section.4);
        let sections = raw
            .iter()
            .map(|&(name, kind, link, addr, data)| Section {
                name: c_str(names, name as usize),
                kind,
                link,
                addr,
                data,
            })
            .collect();
        Some(Self {
            image,
            sections,
            loads,
            tls,
            machine: u16_at(image, 0x12)?,
        })
    }

    pub fn section(&self, name: &str) -> Option<&'a [u8]> {
        self.sections
            .iter()
            .find(|section| section.name == name.as_bytes())
            .map(|section| section.data)
    }

    /// The address a section is loaded at.
    pub fn section_addr(&self, name: &str) -> Option<u64> {
        self.sections
            .iter()
            .find(|section| section.name == name.as_bytes())
            .map(|section| section.addr)
    }

    /// Where the byte loaded at `addr` is in the file: what a uprobe is
    /// attached by.
    pub fn file_offset(&self, addr: u64) -> Option<u64> {
        self.loads
            .iter()
            .find(|&&(start, _, size)| addr >= start && addr - start < size)
            .map(|&(start, offset, _)| addr - start + offset)
    }

    /// The `len` bytes the file holds at address `addr`, if it holds them.
    pub fn bytes_at(&self, addr: u64, len: usize) -> Option<&'a [u8]> {
        let at = usize::try_from(self.file_offset(addr)?).ok()?;
        self.image.get(at..at.checked_add(len)?)
    }

    /// Addresses of the functions whose symbol names contain every one of
    /// `parts`, in ascending order, each once.
    pub fn functions(&self, parts: &[&str]) -> Vec<u64> {
        let Some(symtab) = self.sections.iter().find(|s| s.kind == SHT_SYMTAB) else {
            return Vec::new();
        };
        let strings = self
            .sections
            .get(symtab.link as usize)
            .map_or(&[][..], |section| section.data);
        let mut found: Vec<u64> = symtab
            .data
            .chunks_exact(24)
            .filter(|symbol| symbol[4] & 0xf == STT_FUNC)
            .filter(|symbol| {
                let name = c_str(strings, u32_at(symbol, 0).unwrap_or(0) as usize);
                parts
                    .iter()
                    .all(|part| find(name, part.as_bytes()).is_some())
            })
            .filter_map(|symbol| u64_at(symbol, 8))
            .filter(|addr| *addr != 0)
            .collect();
        found.sort_unstable();
        found.dedup();
        found
    }

    /// Addresses of the functions whose symbol names `is` accepts, in
    /// ascending order, each once.
    pub fn functions_where(&self, is: impl Fn(&[u8]) -> bool) -> Vec<u64> {
        let Some(symtab) = self.sections.iter().find(|s| s.kind == SHT_SYMTAB) else {
            return Vec::new();
        };
        let strings = self
            .sections
            .get(symtab.link as usize)
            .map_or(&[][..], |section| section.data);
        let mut found: Vec<u64> = symtab
            .data
            .chunks_exact(24)
            .filter(|symbol| symbol[4] & 0xf == STT_FUNC)
            .filter(|symbol| is(c_str(strings, u32_at(symbol, 0).unwrap_or(0) as usize)))
            .filter_map(|symbol| u64_at(symbol, 8))
            .filter(|addr| *addr != 0)
            .collect();
        found.sort_unstable();
        found.dedup();
        found
    }

    /// Addresses of the functions a shared library exports whose names `is`
    /// accepts, in ascending order, each once. From the dynamic symbol table,
    /// which a library keeps when it is stripped.
    pub fn exported_functions_where(&self, is: impl Fn(&[u8]) -> bool) -> Vec<u64> {
        let Some(symtab) = self.sections.iter().find(|s| s.kind == SHT_DYNSYM) else {
            return Vec::new();
        };
        let strings = self
            .sections
            .get(symtab.link as usize)
            .map_or(&[][..], |section| section.data);
        let mut found: Vec<u64> = symtab
            .data
            .chunks_exact(24)
            .filter(|symbol| symbol[4] & 0xf == STT_FUNC)
            .filter(|symbol| is(c_str(strings, u32_at(symbol, 0).unwrap_or(0) as usize)))
            .filter_map(|symbol| u64_at(symbol, 8))
            .filter(|addr| *addr != 0)
            .collect();
        found.sort_unstable();
        found.dedup();
        found
    }

    /// Offset in the TLS segment of the thread-local whose symbol name
    /// contains `part`; the lowest, if several do (a thread-local and its
    /// companions are laid out together, the value first).
    pub fn tls_symbol(&self, part: &str) -> Option<u64> {
        let symtab = self.sections.iter().find(|s| s.kind == SHT_SYMTAB)?;
        let strings = self.sections.get(symtab.link as usize)?.data;
        symtab
            .data
            .chunks_exact(24)
            .filter(|symbol| symbol[4] & 0xf == STT_TLS)
            .filter(|symbol| {
                let name = c_str(strings, u32_at(symbol, 0).unwrap_or(0) as usize);
                find(name, part.as_bytes()).is_some()
            })
            .filter_map(|symbol| u64_at(symbol, 8))
            .min()
    }
}

/// Where `needle` first occurs in `haystack`.
pub(crate) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let first = needle[0];
    let mut from = 0;
    while let Some(at) = haystack[from..].iter().position(|b| *b == first) {
        let start = from + at;
        if haystack[start..].starts_with(needle) {
            return Some(start);
        }
        from = start + 1;
    }
    None
}
