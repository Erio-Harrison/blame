//! HPACK (RFC 7541) decoding: what `h2meta` needs to turn the header blocks
//! of an HTTP/2 connection back into names and values.
//!
//! A decoder follows one direction of one connection. Its dynamic table is
//! built from every block of that direction, in order; a block that cannot
//! be decoded leaves the table in an unknown state, and the decoder must
//! not be used again.
//!
//! A decoder can also start in the middle of a connection
//! ([`Decoder::joining`]), when what the table held before is not known.
//! The table is addressed from its newest entry, and entries leave from the
//! old end, so the entries added since the decoder started are exactly the
//! newest ones: a reference to one of them is to the same entry in the real
//! table, and a reference past them is to something added before, which is
//! not known. Fields are reported only when both name and value are known;
//! nothing is ever guessed. How much the real table holds is not known
//! either, so nothing is dropped for size (keeping an entry the real table
//! has dropped is harmless: the encoder cannot refer to it).
//!
//! Written for the rate at which blocks arrive (three per gRPC call, for
//! every call of every traced server): nothing is allocated per block
//! except the table entries a block adds, and Huffman-coded strings are
//! decoded by walking a tree that is built once.

use std::{collections::VecDeque, sync::OnceLock};

#[path = "hpack_tables.rs"]
mod tables;

use tables::{HUFFMAN_CODES, STATIC_TABLE};

/// The table size both ends start with (SETTINGS_HEADER_TABLE_SIZE).
const TABLE_DEFAULT: usize = 4096;
/// What an entry costs on top of its name and value (RFC 7541, 4.1).
const ENTRY_OVERHEAD: usize = 32;
const EOS: u16 = 256;
/// A node of the Huffman tree: a symbol, or where each bit leads.
const LEAF: u16 = 0x8000;

/// A block that is not valid HPACK for the table as it is known here.
#[derive(Debug, PartialEq, Eq)]
pub struct Broken;

/// `tree[node][bit]` is the next node, or `LEAF | symbol`.
fn huffman_tree() -> &'static [[u16; 2]] {
    static TREE: OnceLock<Vec<[u16; 2]>> = OnceLock::new();
    TREE.get_or_init(|| {
        let mut tree = vec![[0u16; 2]];
        for (symbol, &(code, bits)) in HUFFMAN_CODES.iter().enumerate() {
            let mut node = 0usize;
            for i in (0..bits).rev() {
                let bit = (code >> i & 1) as usize;
                if i == 0 {
                    tree[node][bit] = LEAF | symbol as u16;
                } else {
                    if tree[node][bit] == 0 {
                        tree.push([0; 2]);
                        tree[node][bit] = (tree.len() - 1) as u16;
                    }
                    node = usize::from(tree[node][bit]);
                }
            }
        }
        tree
    })
}

/// Decode a Huffman-coded string into `out` (cleared first).
fn huffman_decode(coded: &[u8], out: &mut Vec<u8>) -> Result<(), Broken> {
    let tree = huffman_tree();
    out.clear();
    let mut node = 0usize;
    // Bits since the last symbol, and whether they were all ones: the only
    // padding allowed is fewer than eight bits of the end-of-string code.
    let mut pending = 0u32;
    let mut all_ones = true;
    for &byte in coded {
        for i in (0..8).rev() {
            let bit = usize::from(byte >> i & 1);
            let next = tree[node][bit];
            pending += 1;
            all_ones &= bit == 1;
            if next & LEAF != 0 {
                let symbol = next & !LEAF;
                if symbol == EOS {
                    return Err(Broken);
                }
                out.push(symbol as u8);
                node = 0;
                pending = 0;
                all_ones = true;
            } else if next == 0 {
                return Err(Broken);
            } else {
                node = usize::from(next);
            }
        }
    }
    if pending >= 8 || !all_ones {
        return Err(Broken);
    }
    Ok(())
}

/// An integer with an N-bit prefix (5.1); returns it and the bytes used.
fn integer(buf: &[u8], prefix_bits: u8) -> Result<(usize, usize), Broken> {
    let mask = (1u16 << prefix_bits) as usize - 1;
    let mut value = usize::from(*buf.first().ok_or(Broken)?) & mask;
    if value < mask {
        return Ok((value, 1));
    }
    let mut shift = 0u32;
    for (i, &byte) in buf[1..].iter().enumerate() {
        // Far beyond any length or index that could be meant.
        if shift > 28 {
            return Err(Broken);
        }
        value += usize::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((value, i + 2));
        }
    }
    Err(Broken)
}

/// A header field of the dynamic table: name and value. The name is `None`
/// when it was given by reference to an entry from before the decoder
/// started.
type Entry = (Option<Box<[u8]>>, Box<[u8]>);

/// Entries a decoder that started mid-connection keeps: far more than a
/// table of any usual size holds.
const JOINING_ENTRIES: usize = 4096;

pub struct Decoder {
    /// Newest first.
    table: VecDeque<Entry>,
    size: usize,
    max_size: usize,
    /// The largest table the encoder may be told to use.
    max_allowed: usize,
    /// Started mid-connection: entries older than `table`'s exist and are
    /// not known.
    joining: bool,
    /// Scratch for Huffman-decoded strings.
    name: Vec<u8>,
    value: Vec<u8>,
}

impl Decoder {
    pub fn new(max_allowed: usize) -> Self {
        Self {
            table: VecDeque::new(),
            size: 0,
            max_size: TABLE_DEFAULT,
            max_allowed: max_allowed.max(TABLE_DEFAULT),
            joining: false,
            name: Vec::new(),
            value: Vec::new(),
        }
    }

    /// A decoder for a direction that is already under way: see the module
    /// documentation.
    pub fn joining(max_allowed: usize) -> Self {
        Self {
            joining: true,
            ..Self::new(max_allowed)
        }
    }

    fn evict_to(&mut self, limit: usize) {
        while self.size > limit {
            match self.table.pop_back() {
                Some((name, value)) => {
                    self.size -= name.map_or(0, |name| name.len()) + value.len() + ENTRY_OVERHEAD;
                }
                None => break,
            }
        }
    }

    fn insert(&mut self, name: Option<&[u8]>, value: &[u8]) {
        if self.joining {
            // The real table's size is not known: keep everything recent.
            self.table.push_front((name.map(Into::into), value.into()));
            self.table.truncate(JOINING_ENTRIES);
            return;
        }
        let cost = name.map_or(0, <[u8]>::len) + value.len() + ENTRY_OVERHEAD;
        // An entry larger than the table empties it (4.4).
        self.evict_to(self.max_size.saturating_sub(cost));
        if cost <= self.max_size {
            self.table.push_front((name.map(Into::into), value.into()));
            self.size += cost;
        }
    }

    /// A string literal (5.2) into `out`; returns the bytes used.
    fn string(buf: &[u8], out: &mut Vec<u8>) -> Result<usize, Broken> {
        let huffman = buf.first().ok_or(Broken)? & 0x80 != 0;
        let (len, used) = integer(buf, 7)?;
        let raw = buf.get(used..used + len).ok_or(Broken)?;
        if huffman {
            huffman_decode(raw, out)?;
        } else {
            out.clear();
            out.extend_from_slice(raw);
        }
        Ok(used + len)
    }

    /// Decode one whole header block, calling `field(name, value)` for each
    /// header field in it, in order.
    pub fn decode(
        &mut self,
        block: &[u8],
        mut field: impl FnMut(&[u8], &[u8]),
    ) -> Result<(), Broken> {
        let mut at = 0;
        while at < block.len() {
            let first = block[at];
            if first & 0x80 != 0 {
                // Indexed header field (6.1).
                let (index, used) = integer(&block[at..], 7)?;
                at += used;
                if let Some((Some(name), value)) = self.entry(index)? {
                    field(name, value);
                }
                continue;
            }
            if first & 0xe0 == 0x20 {
                // Dynamic table size update (6.3).
                let (size, used) = integer(&block[at..], 5)?;
                at += used;
                if size > self.max_allowed {
                    return Err(Broken);
                }
                self.max_size = size;
                if !self.joining {
                    self.evict_to(size);
                } else if size == 0 {
                    // The real table is empty: from here on all of it is known.
                    self.table.clear();
                    self.size = 0;
                    self.joining = false;
                }
                continue;
            }
            // A literal: added to the table (6.2.1), or not (6.2.2, 6.2.3).
            let indexed = first & 0xc0 == 0x40;
            let (name_index, used) = integer(&block[at..], if indexed { 6 } else { 4 })?;
            at += used;
            let mut name = std::mem::take(&mut self.name);
            let mut value = std::mem::take(&mut self.value);
            let mut named = true;
            let done = (|| {
                if name_index == 0 {
                    at += Self::string(&block[at..], &mut name)?;
                } else {
                    match self.entry(name_index)? {
                        Some((Some(known), _)) => {
                            name.clear();
                            name.extend_from_slice(known);
                        }
                        _ => named = false,
                    }
                }
                at += Self::string(&block[at..], &mut value)?;
                Ok(())
            })();
            if done.is_ok() {
                if named {
                    field(&name, &value);
                }
                if indexed {
                    self.insert(named.then_some(&name[..]), &value);
                }
            }
            self.name = name;
            self.value = value;
            done?;
        }
        Ok(())
    }

    /// The entry at an index of the combined address space (2.3.3): its
    /// name, if known, and its value. `None`: an entry from before a
    /// joining decoder started.
    #[allow(clippy::type_complexity)]
    fn entry(&self, index: usize) -> Result<Option<(Option<&[u8]>, &[u8])>, Broken> {
        if index == 0 {
            return Err(Broken);
        }
        if let Some(&(name, value)) = STATIC_TABLE.get(index - 1) {
            return Ok(Some((Some(name), value)));
        }
        match self.table.get(index - 1 - STATIC_TABLE.len()) {
            Some((name, value)) => Ok(Some((name.as_deref(), &value[..]))),
            None if self.joining => Ok(None),
            None => Err(Broken),
        }
    }
}

/// An encoder for tests, which uses the dynamic table the way real ones do
/// (a field sent before is sent as a reference; a new one is added): what a
/// decoder that joins late has to cope with. No Huffman coding.
#[cfg(test)]
pub(crate) struct TestEncoder {
    table: VecDeque<(Vec<u8>, Vec<u8>)>,
    size: usize,
}

#[cfg(test)]
impl TestEncoder {
    pub(crate) fn new() -> Self {
        Self {
            table: VecDeque::new(),
            size: 0,
        }
    }

    fn integer(out: &mut Vec<u8>, first: u8, prefix_bits: u8, mut value: usize) {
        let mask = (1usize << prefix_bits) - 1;
        if value < mask {
            out.push(first | value as u8);
            return;
        }
        out.push(first | mask as u8);
        value -= mask;
        while value >= 128 {
            out.push((value % 128) as u8 | 0x80);
            value /= 128;
        }
        out.push(value as u8);
    }

    pub(crate) fn encode(&mut self, fields: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(name, value) in fields {
            let (name, value) = (name.as_bytes(), value.as_bytes());
            let all = |(n, v): (&[u8], &[u8])| n == name && v == value;
            let whole = STATIC_TABLE
                .iter()
                .position(|&(n, v)| all((n, v)))
                .map(|i| i + 1)
                .or_else(|| {
                    self.table
                        .iter()
                        .position(|(n, v)| all((n, v)))
                        .map(|i| i + 1 + STATIC_TABLE.len())
                });
            if let Some(index) = whole {
                Self::integer(&mut out, 0x80, 7, index);
                continue;
            }
            // Literal with incremental indexing; the name by reference to
            // the static table when it is there.
            match STATIC_TABLE.iter().position(|&(n, _)| n == name) {
                Some(i) => Self::integer(&mut out, 0x40, 6, i + 1),
                None => {
                    out.push(0x40);
                    Self::integer(&mut out, 0, 7, name.len());
                    out.extend_from_slice(name);
                }
            }
            Self::integer(&mut out, 0, 7, value.len());
            out.extend_from_slice(value);
            let cost = name.len() + value.len() + ENTRY_OVERHEAD;
            while self.size + cost > TABLE_DEFAULT {
                match self.table.pop_back() {
                    Some((n, v)) => self.size -= n.len() + v.len() + ENTRY_OVERHEAD,
                    None => break,
                }
            }
            if cost <= TABLE_DEFAULT {
                self.table.push_front((name.to_vec(), value.to_vec()));
                self.size += cost;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(decoder: &mut Decoder, block: &[u8]) -> Result<Vec<(String, String)>, Broken> {
        let mut out = Vec::new();
        decoder.decode(block, |name, value| {
            out.push((
                String::from_utf8_lossy(name).into_owned(),
                String::from_utf8_lossy(value).into_owned(),
            ));
        })?;
        Ok(out)
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
        digits
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    /// RFC 7541, C.4: three requests on one connection, Huffman-coded, each
    /// building on the table the ones before left.
    #[test]
    fn the_request_examples_of_the_rfc_decode() {
        let mut decoder = Decoder::new(TABLE_DEFAULT);
        assert_eq!(
            fields(
                &mut decoder,
                &hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff")
            ),
            Ok(pairs(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ]))
        );
        assert_eq!(
            fields(&mut decoder, &hex("8286 84be 5886 a8eb 1064 9cbf")),
            Ok(pairs(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ]))
        );
        assert_eq!(
            fields(
                &mut decoder,
                &hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf")
            ),
            Ok(pairs(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value"),
            ]))
        );
        assert_eq!(decoder.size, 164);
    }

    /// RFC 7541, C.5: responses with a 256-byte table, so entries are evicted.
    #[test]
    fn the_response_examples_of_the_rfc_decode_with_eviction() {
        let mut decoder = Decoder::new(TABLE_DEFAULT);
        decoder.max_size = 256;
        let first = hex(
            "4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 \
             2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 \
             6c65 2e63 6f6d",
        );
        assert_eq!(
            fields(&mut decoder, &first),
            Ok(pairs(&[
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ]))
        );
        assert_eq!(decoder.size, 222);
        // ":status: 307" pushes ":status: 302" out.
        assert_eq!(
            fields(&mut decoder, &hex("4803 3330 37c1 c0bf")),
            Ok(pairs(&[
                (":status", "307"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ]))
        );
        assert_eq!(decoder.size, 222);
    }

    #[test]
    fn what_another_implementation_encodes_is_decoded_the_same() {
        let mut encoder = fluke_hpack::Encoder::new();
        let mut decoder = Decoder::new(TABLE_DEFAULT);
        let mut seed = 12345u32;
        let mut next = move || {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            seed >> 16
        };
        for round in 0..2000 {
            let mut wanted = Vec::new();
            for _ in 0..1 + next() % 6 {
                // Few names, many values: entries are reused and evicted.
                let name = format!("x-header-{}", next() % 7);
                let value: String = (0..next() % 60)
                    .map(|_| char::from(32 + (next() % 95) as u8))
                    .collect();
                wanted.push((name, value));
            }
            wanted.push((":path".to_string(), format!("/svc.S/M{}", round % 5)));
            let block = encoder.encode(wanted.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes())));
            assert_eq!(fields(&mut decoder, &block), Ok(wanted), "round {round}");
        }
    }

    /// A decoder that starts in the middle of a connection says less than
    /// one that saw it all, and never anything different.
    #[test]
    fn a_decoder_that_joins_late_reports_only_what_it_can_know() {
        let mut encoder = TestEncoder::new();
        // Another implementation follows the whole connection: the test
        // encoder's output is real HPACK, and this is what it means.
        let mut reference = fluke_hpack::Decoder::new();
        let mut late = Decoder::joining(TABLE_DEFAULT);
        let mut seed = 99u32;
        let mut next = move || {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            seed >> 16
        };
        let (mut unknown_paths, mut last_unknown, mut unknown_agents) = (0usize, 0usize, 0usize);
        for round in 0..1200usize {
            // What a gRPC client sends: the same few paths over and over, a
            // header that is new on every call, some that never change.
            let path = format!("/svc.S/M{}", next() % 4);
            let trace = format!("00-{:032x}-{:016x}-01", next(), round);
            let wanted = [
                (":method", "POST"),
                (":path", path.as_str()),
                ("content-type", "application/grpc"),
                ("user-agent", "grpc-go/1.85.0"),
                ("traceparent", trace.as_str()),
            ];
            let block = encoder.encode(&wanted);
            let all: Vec<(String, String)> = reference
                .decode(&block)
                .unwrap()
                .into_iter()
                .map(|(n, v)| (String::from_utf8(n).unwrap(), String::from_utf8(v).unwrap()))
                .collect();
            assert_eq!(all, pairs(&wanted), "round {round}");
            if round < 100 {
                continue;
            }
            // Joined after 100 blocks. Everything it reports is a field of
            // the block, in order.
            let some = fields(&mut late, &block).unwrap();
            let mut rest = all.iter();
            for field in &some {
                assert!(
                    rest.any(|f| f == field),
                    "round {round}: {field:?} not in {all:?}"
                );
            }
            // The trace id is new on every call: always spelled out.
            assert!(some.iter().any(|(name, _)| name == "traceparent"));
            if !some.iter().any(|(name, _)| name == ":path") {
                unknown_paths += 1;
                last_unknown = round;
            }
            unknown_agents += usize::from(!some.iter().any(|(name, _)| name == "user-agent"));
        }
        // The paths were in the table before the decoder joined: references
        // it cannot follow. But a new trace id on every call pushes old
        // entries out, so each path is soon sent spelled out again.
        assert!(unknown_paths > 0);
        assert!(last_unknown < 200, "{last_unknown}");
        // (A header that never changes and is always in use goes the same way.)
        assert!(
            unknown_agents > 0 && unknown_agents < 100,
            "{unknown_agents}"
        );
    }

    #[test]
    fn blocks_that_make_no_sense_are_refused() {
        let mut decoder = Decoder::new(TABLE_DEFAULT);
        // Index 0, an index past both tables, a string longer than the block.
        assert_eq!(fields(&mut decoder, &[0x80]), Err(Broken));
        assert_eq!(fields(&mut decoder, &[0xff, 0x00]), Err(Broken));
        assert_eq!(fields(&mut decoder, &[0x40, 0x05, b'a']), Err(Broken));
        // Huffman: the end-of-string symbol inside a string, a whole byte of
        // padding, padding that is not ones.
        let mut out = Vec::new();
        assert_eq!(
            huffman_decode(&[0xff, 0xff, 0xff, 0xff], &mut out),
            Err(Broken)
        );
        assert_eq!(huffman_decode(&[0x1f, 0xff], &mut out), Err(Broken));
        assert_eq!(huffman_decode(&[0x18], &mut out), Err(Broken));
        // 'a' is 00011, then three ones of padding.
        assert_eq!(huffman_decode(&[0x1f], &mut out), Ok(()));
        assert_eq!(out, b"a");
        // A size update beyond what is allowed.
        let mut small = Decoder::new(TABLE_DEFAULT);
        assert_eq!(fields(&mut small, &[0x3f, 0xe1, 0xff, 0x03]), Err(Broken));
    }
}
