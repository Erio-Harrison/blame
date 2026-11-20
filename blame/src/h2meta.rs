//! What an HTTP/2 request is: its path (for gRPC, the method), the trace it
//! belongs to and the gRPC status it ended with.
//!
//! These are in the header blocks, compressed with HPACK against a table
//! that both ends build up over the life of the connection. The kernel side
//! passes every header block of a client-facing connection on, in order,
//! and one decoder per direction is kept here. A direction that was followed
//! from the connection's first byte, with no part of any block missed, is
//! decoded in full. One that was not (the connection is older than the
//! agent, or events were lost) is decoded from where it is picked up, by a
//! decoder that knows what it cannot know (`hpack::Decoder::joining`): the
//! fields it gives are right, and those it cannot give are left out. A
//! wrong table would give wrong names; nothing here guesses.
//!
//! What a joining decoder cannot give, the server process itself can: it has
//! decoded the headers. Probes in it (runtime/go_grpc.h, runtime/rust_h2.h)
//! send the trace id, the path and the status of each stream of such a
//! connection as `H2Fields` events, kept here until the stream's request is
//! shown. They fill in only what the header blocks did not give, and only
//! for the request they belong to: the time they were read is checked against
//! the request's.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    rc::Rc,
};

use blame_common::{
    H2F_PATH_LEN, H2F_REQUEST, H2F_RESPONSE, H2Fields, H2H_FRAME_START, H2H_FROM_START, H2Headers,
};

use crate::hpack::Decoder;

const FRAME_HEADERS: u8 = 1;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

/// A peer may be told a larger table than the default; follow it up to this.
const TABLE_MAX: usize = 1 << 20;
/// Streams kept per connection whose end was never seen (reset streams).
const STREAMS_PER_CONN: usize = 4096;
/// Stream ids remembered per connection as opened.
const OPENED_PER_CONN: usize = 4096;
/// Finished streams kept until their request is shown, or pushed out.
const FINISHED_MAX: usize = 16384;
/// Streams whose fields were read in the process and not yet shown.
const FIELDS_MAX: usize = 16384;
/// A field read in the process may be this far outside its request's span:
/// the clocks are one, so this is only for the order of two reads.
const FIELDS_SLACK_NS: u64 = 1_000_000;
/// Connections kept; the least recently used go first.
const CONNS_MAX: usize = 8192;
/// Different paths kept as one string each; past that, each use has its own.
const PATHS_MAX: usize = 4096;

/// What the header blocks of one stream said. Every request on a decodable
/// connection gets one, shown or not, so it is cheap to make: paths are
/// shared, the trace id is held in place.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Meta {
    /// `:path`: `/package.Service/Method` for gRPC.
    pub path: Option<Rc<str>>,
    /// The trace id of a W3C `traceparent` header: 32 hex digits.
    pub trace: Option<[u8; 32]>,
    /// `grpc-status`.
    pub grpc_status: Option<u32>,
}

impl Meta {
    pub fn trace(&self) -> Option<&str> {
        self.trace
            .as_ref()
            .and_then(|id| std::str::from_utf8(id).ok())
    }
}

/// What the process said of one stream (see `H2Meta::on_fields`), and when:
/// the first and the last time it was read.
struct Fields {
    /// Which `on_fields` made it: the queue of what to forget first names it.
    generation: u64,
    /// When the request's headers were read, and when the status was
    /// written: each must fall in the request's span to be its own. Apart,
    /// because a handler goes on after a call it was given up on, and writes
    /// a status after the request is over.
    request_ns: Option<u64>,
    status_ns: Option<u64>,
    path: Option<Rc<str>>,
    trace: Option<[u8; 32]>,
    status: Option<u32>,
}

struct Dir {
    decoder: Decoder,
    next_seq: u32,
    /// Picked up in the middle of a block: wait for the next one to start.
    midway: bool,
    /// Payload of the frame being received.
    frame: Vec<u8>,
    /// Fragments of the block being received, and what its first frame said.
    block: Vec<u8>,
    block_sid: u32,
    block_ends_stream: bool,
}

impl Dir {
    /// `whole`: the direction is followed from the connection's first byte.
    fn new(whole: bool) -> Self {
        Self {
            decoder: if whole {
                Decoder::new(TABLE_MAX)
            } else {
                Decoder::joining(TABLE_MAX)
            },
            next_seq: 0,
            midway: !whole,
            frame: Vec::new(),
            block: Vec::new(),
            block_sid: 0,
            block_ends_stream: false,
        }
    }
}

struct Conn {
    rx: Dir,
    tx: Dir,
    streams: BTreeMap<u32, Meta>,
    opened: BTreeSet<u32>,
    used: u64,
}

#[derive(Default)]
pub struct H2Meta {
    conns: HashMap<u64, Conn>,
    finished: HashMap<(u64, u32), Meta>,
    order: VecDeque<(u64, u32)>,
    paths: HashMap<Box<[u8]>, Rc<str>>,
    fields: HashMap<(u64, u32), Fields>,
    fields_order: VecDeque<((u64, u32), u64)>,
    fields_generation: u64,
    clock: u64,
}

/// The trace id in `00-<32 hex>-<16 hex>-<2 hex>`.
fn trace_id(traceparent: &[u8]) -> Option<[u8; 32]> {
    let id: [u8; 32] = traceparent.get(3..35)?.try_into().ok()?;
    (traceparent.get(2) == Some(&b'-')
        && traceparent.get(35) == Some(&b'-')
        && id.iter().all(u8::is_ascii_hexdigit))
    .then_some(id)
}

/// A trace or span id as the header spells it: hex digits, not all zero.
fn valid_id(id: &[u8]) -> bool {
    id.iter().all(u8::is_ascii_hexdigit) && id.iter().any(|&b| b != b'0')
}

/// One string per path: services have a handful of methods and call them
/// millions of times.
fn shared_path(paths: &mut HashMap<Box<[u8]>, Rc<str>>, path: &[u8]) -> Rc<str> {
    if let Some(known) = paths.get(path) {
        return Rc::clone(known);
    }
    let text: Rc<str> = Rc::from(String::from_utf8_lossy(path).as_ref());
    if paths.len() < PATHS_MAX {
        paths.insert(path.into(), Rc::clone(&text));
    }
    text
}

/// The header block fragment in a frame's payload.
fn fragment(frame_type: u8, flags: u8, payload: &[u8]) -> Option<&[u8]> {
    if frame_type != FRAME_HEADERS {
        return Some(payload);
    }
    let mut rest = payload;
    if flags & FLAG_PADDED != 0 {
        let pad = usize::from(*rest.first()?);
        rest = rest.get(1..rest.len().checked_sub(pad)?)?;
    }
    if flags & FLAG_PRIORITY != 0 {
        rest = rest.get(5..)?;
    }
    Some(rest)
}

impl H2Meta {
    /// One part of a header block, as the kernel side sent it.
    pub fn on_headers(&mut self, head: &H2Headers, data: &[u8]) {
        self.clock += 1;
        if self.conns.len() >= CONNS_MAX && !self.conns.contains_key(&head.conn) {
            self.drop_idle();
        }
        let conn = self.conns.entry(head.conn).or_insert_with(|| Conn {
            rx: Dir::new(false),
            tx: Dir::new(false),
            streams: BTreeMap::new(),
            opened: BTreeSet::new(),
            used: 0,
        });
        conn.used = self.clock;
        let tx = head.tx != 0;
        if head.seq == 0 {
            // The direction got in step: a new connection, or one picked up
            // again after it was lost.
            if !tx {
                conn.streams.clear();
                conn.opened.clear();
                conn.tx = Dir::new(false);
            }
            let dir = if tx { &mut conn.tx } else { &mut conn.rx };
            *dir = Dir::new(head.bits & H2H_FROM_START != 0);
        }
        let dir = if tx { &mut conn.tx } else { &mut conn.rx };
        if head.seq != dir.next_seq {
            // Parts were lost: what they did to the table is not known.
            *dir = Dir::new(false);
        }
        dir.next_seq = head.seq.wrapping_add(1);
        let starts_frame = head.bits & H2H_FRAME_START != 0;
        if !tx && starts_frame && head.frame_type == FRAME_HEADERS {
            conn.opened.insert(head.sid);
            if conn.opened.len() > OPENED_PER_CONN {
                conn.opened.pop_first();
            }
        }
        if dir.midway {
            // A block starts with a HEADERS frame.
            if !(starts_frame && head.frame_type == FRAME_HEADERS) {
                return;
            }
            dir.midway = false;
        }
        if starts_frame {
            dir.frame.clear();
        }
        dir.frame.extend_from_slice(data);
        if head.left != 0 {
            return;
        }
        let Some(part) = fragment(head.frame_type, head.frame_flags, &dir.frame) else {
            let seq = dir.next_seq;
            *dir = Dir::new(false);
            dir.next_seq = seq;
            return;
        };
        if head.frame_type == FRAME_HEADERS {
            dir.block.clear();
            dir.block_sid = head.sid;
            dir.block_ends_stream = head.frame_flags & FLAG_END_STREAM != 0;
        }
        dir.block.extend_from_slice(part);
        if head.frame_flags & FLAG_END_HEADERS == 0 {
            return;
        }
        let sid = dir.block_sid;
        let ends = tx && dir.block_ends_stream;
        let meta = conn.streams.entry(sid).or_default();
        let paths = &mut self.paths;
        let decoded = dir
            .decoder
            .decode(&dir.block, |name, value| match (tx, name) {
                (false, b":path") => meta.path = Some(shared_path(paths, value)),
                (false, b"traceparent") => meta.trace = trace_id(value),
                (true, b"grpc-status") => {
                    meta.grpc_status = std::str::from_utf8(value).ok().and_then(|v| v.parse().ok());
                }
                _ => {}
            });
        if decoded.is_err() {
            // What the block said before it broke is not to be trusted
            // either, nor the table after it: start over from the next block.
            conn.streams.remove(&sid);
            let seq = dir.next_seq;
            *dir = Dir::new(false);
            dir.next_seq = seq;
            return;
        }
        if ends {
            if let Some(meta) = conn.streams.remove(&sid) {
                self.finish(head.conn, sid, meta);
            }
        } else if conn.streams.len() > STREAMS_PER_CONN {
            conn.streams.pop_first();
        }
    }

    /// What the server process read of a stream's headers or its status.
    /// A request's fields start a stream's entry; a status joins it.
    pub fn on_fields(&mut self, e: &H2Fields) {
        let key = (e.conn, e.sid);
        let at = e.hdr.ts_boot_ns;
        let trace = (e.has_trace != 0)
            .then(|| <[u8; 32]>::try_from(&e.trace[..]).ok())
            .flatten()
            .filter(|id| valid_id(id));
        let path = (e.what == H2F_REQUEST && e.path_len != 0)
            .then(|| self.path_from_process(e.path_bytes()))
            .flatten();
        // gRPC status codes are 0 to 16.
        let status = (e.has_status != 0 && e.status <= 16).then_some(e.status);
        if e.what == H2F_REQUEST {
            self.fields.remove(&key);
        }
        let generation = self.fields_generation;
        let entry = self.fields.entry(key).or_insert_with(|| {
            self.fields_order.push_back((key, generation));
            Fields {
                generation,
                request_ns: None,
                status_ns: None,
                path: None,
                trace: None,
                status: None,
            }
        });
        if e.what == H2F_REQUEST {
            entry.request_ns = Some(at);
            entry.path = path;
            entry.trace = trace;
        } else if e.what == H2F_RESPONSE {
            entry.status_ns = Some(at);
            entry.status = status;
        }
        self.fields_generation += 1;
        while self.fields_order.len() > FIELDS_MAX {
            if let Some((old, generation)) = self.fields_order.pop_front()
                && self
                    .fields
                    .get(&old)
                    .is_some_and(|f| f.generation == generation)
            {
                self.fields.remove(&old);
            }
        }
    }

    /// `/package.Service/Method` as the process holds it. A path that fills
    /// the space for it may have been cut: not taken.
    fn path_from_process(&mut self, path: &[u8]) -> Option<Rc<str>> {
        let ok = path.len() < H2F_PATH_LEN
            && path.first() == Some(&b'/')
            && path.iter().all(|b| (0x21..0x7f).contains(b));
        ok.then(|| shared_path(&mut self.paths, path))
    }

    fn finish(&mut self, conn: u64, sid: u32, meta: Meta) {
        if self.finished.insert((conn, sid), meta).is_none() {
            self.order.push_back((conn, sid));
        }
        while self.order.len() > FINISHED_MAX {
            if let Some(key) = self.order.pop_front() {
                self.finished.remove(&key);
            }
        }
    }

    fn drop_idle(&mut self) {
        let mut ages: Vec<u64> = self.conns.values().map(|conn| conn.used).collect();
        ages.sort_unstable();
        let cut = ages[ages.len() / 4];
        self.conns.retain(|_, conn| conn.used > cut);
    }

    /// What is known about a stream whose request is being shown. `None`
    /// if none of its header blocks was seen.
    pub fn take(&mut self, conn: u64, sid: u32) -> Option<Meta> {
        if let Some(meta) = self.finished.remove(&(conn, sid)) {
            return Some(meta);
        }
        // Its last header block has not come by yet (it was cut across two
        // writes): what there is so far.
        self.conns.get_mut(&conn)?.streams.remove(&sid)
    }

    /// As `take`, with what the server process read of the stream added
    /// where the header blocks gave nothing, if it was read while the request
    /// was in progress (`start_ns` to `end_ns`, boot time): the same stream
    /// id on a later connection that has the same address is not this one.
    pub fn take_at(&mut self, conn: u64, sid: u32, start_ns: u64, end_ns: u64) -> Option<Meta> {
        let within = |at: Option<u64>| {
            at.is_some_and(|at| at + FIELDS_SLACK_NS >= start_ns && at <= end_ns + FIELDS_SLACK_NS)
        };
        // Headers read outside the span are another stream's with the same
        // id (an earlier connection at the same address), and so is its
        // status then.
        let read = self
            .fields
            .remove(&(conn, sid))
            .filter(|f| match f.request_ns {
                Some(_) => within(f.request_ns),
                None => within(f.status_ns),
            });
        let mut meta = self.take(conn, sid);
        if let Some(read) = read {
            let meta = meta.get_or_insert_with(Meta::default);
            meta.path = meta.path.take().or(read.path);
            meta.trace = meta.trace.or(read.trace);
            if within(read.status_ns) {
                meta.grpc_status = meta.grpc_status.or(read.status);
            }
        }
        meta
    }

    /// Whether the client opened this stream on this connection.
    pub fn opened(&self, conn: u64, sid: u32) -> bool {
        self.conns
            .get(&conn)
            .is_some_and(|conn| conn.opened.contains(&sid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blame_common::EventHeader;
    use fluke_hpack::Encoder;

    use crate::hpack::TestEncoder;

    fn head(conn: u64, seq: u32, sid: u32, tx: bool, flags: u8, bits: u8, left: u16) -> H2Headers {
        // SAFETY: plain integers; all zeroes is a valid value.
        let hdr: EventHeader = unsafe { std::mem::zeroed() };
        H2Headers {
            hdr,
            conn,
            seq,
            sid,
            tx: u8::from(tx),
            frame_type: FRAME_HEADERS,
            frame_flags: flags,
            bits,
            len: 0,
            left,
        }
    }

    const WHOLE: u8 = H2H_FRAME_START | H2H_FROM_START;

    #[test]
    fn a_request_and_its_trailers_give_path_trace_and_status() {
        let mut client = Encoder::new();
        let mut server = Encoder::new();
        let mut meta = H2Meta::default();
        for (seq, sid) in [(0u32, 1u32), (1, 3)] {
            let block = client.encode(vec![
                (&b":method"[..], &b"POST"[..]),
                (&b":path"[..], &b"/x.S/U"[..]),
                (
                    &b"traceparent"[..],
                    &b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"[..],
                ),
            ]);
            // Cut in two parts, as a block longer than one event is.
            let (a, b) = block.split_at(block.len() / 2);
            meta.on_headers(
                &head(
                    7,
                    seq * 2,
                    sid,
                    false,
                    FLAG_END_HEADERS,
                    WHOLE,
                    b.len() as u16,
                ),
                a,
            );
            meta.on_headers(
                &head(
                    7,
                    seq * 2 + 1,
                    sid,
                    false,
                    FLAG_END_HEADERS,
                    H2H_FROM_START,
                    0,
                ),
                b,
            );
            assert!(meta.opened(7, sid));
        }
        let trailers = server.encode(vec![(&b"grpc-status"[..], &b"5"[..])]);
        meta.on_headers(
            &head(7, 0, 3, true, FLAG_END_HEADERS | FLAG_END_STREAM, WHOLE, 0),
            &trailers,
        );
        assert_eq!(
            meta.take(7, 3),
            Some(Meta {
                path: Some("/x.S/U".into()),
                trace: Some(*b"4bf92f3577b34da6a3ce929d0e0e4736"),
                grpc_status: Some(5),
            })
        );
        // The other stream has not ended: what its request said.
        assert_eq!(meta.take(7, 1).and_then(|m| m.path), Some("/x.S/U".into()));
        assert_eq!(meta.take(7, 9), None);
    }

    fn fields_event(conn: u64, sid: u32, what: u8, at_ns: u64) -> H2Fields {
        // SAFETY: plain integers and bytes; all zeroes is a valid value.
        let mut e: H2Fields = unsafe { std::mem::zeroed() };
        e.hdr.ts_boot_ns = at_ns;
        e.conn = conn;
        e.sid = sid;
        e.what = what;
        e
    }

    fn request_fields(conn: u64, sid: u32, at_ns: u64, trace: &[u8; 32], path: &str) -> H2Fields {
        let mut e = fields_event(conn, sid, H2F_REQUEST, at_ns);
        e.has_trace = 1;
        e.trace = *trace;
        e.path[..path.len()].copy_from_slice(path.as_bytes());
        e.path_len = path.len() as u8;
        e
    }

    fn status_field(conn: u64, sid: u32, at_ns: u64, status: u32) -> H2Fields {
        let mut e = fields_event(conn, sid, H2F_RESPONSE, at_ns);
        e.has_status = 1;
        e.status = status;
        e
    }

    const TRACE: &[u8; 32] = b"4bf92f3577b34da6a3ce929d0e0e4736";

    #[test]
    fn what_the_process_read_fills_in_what_the_blocks_could_not_give() {
        let mut meta = H2Meta::default();
        meta.on_fields(&request_fields(7, 3, 1_000, TRACE, "/x.S/U"));
        meta.on_fields(&status_field(7, 3, 1_900, 14));
        let got = meta.take_at(7, 3, 900, 2_000).unwrap();
        assert_eq!(got.path.as_deref(), Some("/x.S/U"));
        assert_eq!(got.trace(), Some("4bf92f3577b34da6a3ce929d0e0e4736"));
        assert_eq!(got.grpc_status, Some(14));
        // Used once.
        assert_eq!(meta.take_at(7, 3, 900, 2_000), None);
    }

    #[test]
    fn a_status_written_after_the_request_ended_does_not_take_its_trace_id() {
        // A call the client gave up on after 20 ms: the handler goes on and
        // writes a status 150 ms in, which comes in before the request is
        // shown when both are in one batch of events.
        let mut meta = H2Meta::default();
        meta.on_fields(&request_fields(7, 3, 1_000_000, TRACE, "/x.S/U"));
        meta.on_fields(&status_field(7, 3, 150_000_000, 4));
        let got = meta.take_at(7, 3, 900_000, 20_000_000).unwrap();
        assert_eq!(got.trace(), Some("4bf92f3577b34da6a3ce929d0e0e4736"));
        assert_eq!(got.path.as_deref(), Some("/x.S/U"));
        // Not the request's: written after it was over.
        assert_eq!(got.grpc_status, None);
    }

    #[test]
    fn what_the_blocks_gave_is_kept() {
        let mut client = Encoder::new();
        let mut meta = H2Meta::default();
        let block = client.encode(vec![(&b":path"[..], &b"/from.Blocks/M"[..])]);
        meta.on_headers(&head(7, 0, 5, false, FLAG_END_HEADERS, WHOLE, 0), &block);
        meta.on_fields(&request_fields(7, 5, 1_000, TRACE, "/from.Process/M"));
        let got = meta.take_at(7, 5, 900, 2_000).unwrap();
        assert_eq!(got.path.as_deref(), Some("/from.Blocks/M"));
        assert_eq!(got.trace(), Some("4bf92f3577b34da6a3ce929d0e0e4736"));
    }

    #[test]
    fn a_stream_read_before_or_after_the_request_is_not_its_own() {
        // The same stream id on an earlier connection at the same address.
        let mut meta = H2Meta::default();
        meta.on_fields(&request_fields(7, 3, 1_000_000_000, TRACE, "/old.S/M"));
        assert_eq!(meta.take_at(7, 3, 5_000_000_000, 5_100_000_000), None);
        // A later request's fields do not belong to an earlier one either.
        meta.on_fields(&request_fields(7, 3, 9_000_000_000, TRACE, "/new.S/M"));
        assert_eq!(meta.take_at(7, 3, 5_000_000_000, 5_100_000_000), None);
        // A status with no request fields of its own cannot be joined to old ones.
        meta.on_fields(&request_fields(8, 3, 1_000, TRACE, "/old.S/M"));
        meta.on_fields(&status_field(8, 3, 5_000_000_050, 0));
        assert_eq!(meta.take_at(8, 3, 5_000_000_000, 5_100_000_000), None);
    }

    #[test]
    fn values_that_are_not_what_they_should_be_are_not_taken() {
        let mut meta = H2Meta::default();
        let mut e = request_fields(7, 3, 1_000, b"zzzz2f3577b34da6a3ce929d0e0e4736", "/x.S/U");
        meta.on_fields(&e);
        e.sid = 5;
        e.trace = [b'0'; 32];
        meta.on_fields(&e);
        meta.on_fields(&status_field(7, 3, 1_100, 17));
        let got = meta.take_at(7, 3, 900, 2_000).unwrap();
        assert_eq!(got.path.as_deref(), Some("/x.S/U"));
        assert_eq!((got.trace, got.grpc_status), (None, None));
        assert_eq!(meta.take_at(7, 5, 900, 2_000).unwrap().trace, None);
        // A path that fills the space may have been cut.
        let long = format!("/{}", "a".repeat(H2F_PATH_LEN - 1));
        let mut e = fields_event(7, 9, H2F_REQUEST, 1_000);
        e.path[..long.len()].copy_from_slice(long.as_bytes());
        e.path_len = long.len() as u8;
        meta.on_fields(&e);
        assert_eq!(meta.take_at(7, 9, 900, 2_000).unwrap().path, None);
    }

    #[test]
    fn what_was_read_and_never_shown_is_forgotten_oldest_first() {
        let mut meta = H2Meta::default();
        for sid in 0..(FIELDS_MAX as u32 + 10) {
            meta.on_fields(&request_fields(7, 2 * sid + 1, 1_000, TRACE, "/x.S/U"));
        }
        assert_eq!(meta.fields.len(), FIELDS_MAX);
        assert_eq!(meta.take_at(7, 1, 900, 2_000), None);
        assert!(
            meta.take_at(7, 2 * (FIELDS_MAX as u32 + 9) + 1, 900, 2_000)
                .is_some()
        );
    }

    #[test]
    fn a_connection_picked_up_late_is_named_as_far_as_can_be_known() {
        let mut client = TestEncoder::new();
        let mut meta = H2Meta::default();
        // A call before the agent: /a is in the client's table.
        client.encode(&[(":path", "/a"), ("te", "trailers")]);
        // Not followed from its first byte. /a comes as a reference to an
        // entry from before: not known. /b is new: spelled out.
        let old = client.encode(&[(":path", "/a")]);
        meta.on_headers(
            &head(1, 0, 7, false, FLAG_END_HEADERS, H2H_FRAME_START, 0),
            &old,
        );
        assert_eq!(meta.take(1, 7), Some(Meta::default()));
        let new = client.encode(&[(":path", "/b")]);
        meta.on_headers(
            &head(1, 1, 9, false, FLAG_END_HEADERS, H2H_FRAME_START, 0),
            &new,
        );
        assert_eq!(meta.take(1, 9).and_then(|m| m.path), Some("/b".into()));
        // ... and from then on it is in the part of the table that is known.
        let again = client.encode(&[(":path", "/b")]);
        assert_eq!(again.len(), 1);
        meta.on_headers(
            &head(1, 2, 11, false, FLAG_END_HEADERS, H2H_FRAME_START, 0),
            &again,
        );
        assert_eq!(meta.take(1, 11).and_then(|m| m.path), Some("/b".into()));
    }

    #[test]
    fn after_a_missed_part_nothing_is_taken_from_the_old_table() {
        let mut client = TestEncoder::new();
        let mut meta = H2Meta::default();
        let first = client.encode(&[(":path", "/a")]);
        meta.on_headers(&head(2, 0, 1, false, FLAG_END_HEADERS, WHOLE, 0), &first);
        assert_eq!(meta.take(2, 1).and_then(|m| m.path), Some("/a".into()));
        // A block the agent never got (seq 1) added /lost to the table.
        client.encode(&[(":path", "/lost")]);
        // The next one refers to /a, which is now one entry further back
        // than the agent's table says: with the old table it would come out
        // as /lost's neighbour. It must not come out as anything.
        let next = client.encode(&[(":path", "/a")]);
        assert_eq!(next.len(), 1);
        meta.on_headers(&head(2, 2, 5, false, FLAG_END_HEADERS, WHOLE, 0), &next);
        assert_eq!(meta.take(2, 5), Some(Meta::default()));
        assert!(meta.opened(2, 5));
    }

    #[test]
    fn padding_and_priority_are_not_part_of_the_block() {
        let mut client = Encoder::new();
        let mut meta = H2Meta::default();
        let block = client.encode(vec![(&b":path"[..], &b"/p"[..])]);
        let mut payload = vec![3u8, 0, 0, 0, 0, 16];
        payload.extend(&block);
        payload.extend([0, 0, 0]);
        meta.on_headers(
            &head(
                1,
                0,
                1,
                false,
                FLAG_END_HEADERS | FLAG_PADDED | FLAG_PRIORITY,
                WHOLE,
                0,
            ),
            &payload,
        );
        assert_eq!(meta.take(1, 1).and_then(|m| m.path), Some("/p".into()));
    }
}
