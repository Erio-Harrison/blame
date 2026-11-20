//! What the ring buffer brings in, kept for the main loop; and finding
//! where tokio tasks keep their HTTP/2 stream id, from samples of them.

use blame_common::{
    CgroupMkdirEvent, Counter, EVENT_VERSION, EventHeader, EventKind, H2Fields, H2Headers,
    RequestEvent, TaskSampleEvent,
};
use libbpf_rs::{MapCore, MapFlags};

use crate::{
    bpf::{Skel, percpu_u64_sum},
    h2meta::{H2Meta, Meta},
    json,
    methods::Methods,
    runtime::tasks::{Calibrator, Found},
};

/// A slow request kept for the end of the run, ordered by how long it took
/// (shortest first out of the heap), then by which came first.
pub(super) struct Slowest {
    pub(super) latency_ns: u64,
    pub(super) order: u64,
    pub(super) event: RequestEvent,
    pub(super) what: Option<Meta>,
}

impl PartialEq for Slowest {
    fn eq(&self, other: &Self) -> bool {
        (self.latency_ns, self.order) == (other.latency_ns, other.order)
    }
}
impl Eq for Slowest {}
impl PartialOrd for Slowest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Slowest {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reversed: the heap's top is the one to drop first.
        (other.latency_ns, other.order).cmp(&(self.latency_ns, self.order))
    }
}

/// What the ring buffer callback hands to the main loop.
#[derive(Default)]
pub(super) struct Inbox {
    pub(super) requests: Vec<RequestEvent>,
    pub(super) cgroups: Vec<CgroupMkdirEvent>,
    /// What HTTP/2 streams are, from their header blocks.
    pub(super) meta: H2Meta,
    /// HTTP/2 requests summed up by service and method.
    pub(super) methods: Methods,
    /// Slow requests seen, and those of them listed so far.
    pub(super) slow: u64,
    pub(super) listed: u64,
    /// With `--list N`: the N slowest so far, to be listed at the end.
    pub(super) slowest: std::collections::BinaryHeap<Slowest>,
    /// New tasks to look at, with the values in them that were streams the
    /// client had opened when the task's record came in.
    pub(super) samples: Vec<(TaskSampleEvent, Vec<u32>)>,
    pub(super) calibrator: Calibrator,
    /// Records the ring buffer had dropped when samples were last looked at,
    /// and how many more batches of samples to set aside because of drops.
    pub(super) ring_lost: u64,
    pub(super) samples_unsure: u8,
    /// Records that are not a known event of this build's version.
    pub(super) rejected: u64,
}

pub(super) fn receive(inbox: &mut Inbox, record: &[u8]) {
    let kind = EventHeader::parse(record)
        .filter(|header| header.version == EVENT_VERSION)
        .and_then(|header| EventKind::from_raw(header.kind));
    match kind {
        Some(EventKind::Request) => match RequestEvent::parse(record) {
            Some(event) => inbox.requests.push(*event),
            None => inbox.rejected += 1,
        },
        Some(EventKind::CgroupMkdir) => match CgroupMkdirEvent::parse(record) {
            Some(event) => inbox.cgroups.push(*event),
            None => inbox.rejected += 1,
        },
        Some(EventKind::H2Headers) => match H2Headers::parse(record) {
            Some((head, data)) => inbox.meta.on_headers(head, data),
            None => inbox.rejected += 1,
        },
        Some(EventKind::H2Fields) => match H2Fields::parse(record) {
            Some(event) => inbox.meta.on_fields(event),
            None => inbox.rejected += 1,
        },
        Some(EventKind::TaskSample) => match TaskSampleEvent::parse(record) {
            // Which values are open streams is asked now, in the order the
            // records were written: by the end of the batch the connection
            // may have opened so many streams since that this one's opening
            // is no longer remembered.
            Some(event) => {
                let open = event
                    .mem
                    .chunks_exact(4)
                    .map(|word| u32::from_ne_bytes(word.try_into().expect("four bytes")))
                    .filter(|&value| value & 1 == 1 && inbox.meta.opened(event.conn, value))
                    .collect();
                inbox.samples.push((*event, open));
            }
            None => inbox.rejected += 1,
        },
        Some(EventKind::Exec) | None => inbox.rejected += 1,
    }
}

/// Tell the kernel side where tasks of a kind keep their stream id, once
/// enough new tasks have been looked at to know (or to know they do not).
pub(super) fn place_stream_ids(inbox: &mut Inbox, skel: &Skel, json: bool) {
    let Inbox {
        samples,
        calibrator,
        ring_lost,
        samples_unsure,
        ..
    } = inbox;
    if samples.is_empty() {
        return;
    }
    // A sample rules a place out when the id there is not a stream the
    // client opened, which is known from the header events. If records were
    // dropped, the opening of a stream may be among them, and the right
    // place would be ruled out for good. The kernel side keeps sending
    // samples until there is a verdict, so those of this batch and of the
    // next (where a stream whose opening was dropped may still turn up) are
    // set aside.
    if let Ok(lost) = percpu_u64_sum(&skel.maps.COUNTERS, Counter::RingbufFull as u32)
        && lost > *ring_lost
    {
        *ring_lost = lost;
        *samples_unsure = 2;
    }
    if *samples_unsure > 0 {
        *samples_unsure -= 1;
        samples.clear();
        return;
    }
    for (event, open) in samples.drain(..) {
        let Some(found) = calibrator.sample(&event, |_, sid| open.contains(&sid)) else {
            continue;
        };
        let (a, b) = match found {
            Found::At(a, b) => (a, b),
            // The kernel side's "looked for and not found".
            Found::Nowhere => (u16::MAX, u16::MAX),
        };
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&event.vtable.to_ne_bytes());
        key[8..12].copy_from_slice(&event.hdr.pid.to_ne_bytes());
        let mut value = [0u8; 4];
        value[..2].copy_from_slice(&a.to_ne_bytes());
        value[2..].copy_from_slice(&b.to_ne_bytes());
        match skel
            .maps
            .TASK_STREAM_OFF
            .update(&key, &value, MapFlags::ANY)
        {
            Ok(()) => match found {
                Found::At(a, b) => {
                    let note =
                        format!("stream handlers found (stream id at {a} and {b} in the task)");
                    if json {
                        println!(
                            "{}",
                            json::process(event.hdr.pid, "task", true, Some(&note))
                        );
                    } else {
                        println!("blame: pid {}: {note}", event.hdr.pid);
                    }
                }
                Found::Nowhere => {}
            },
            Err(err) => eprintln!("blame: pid {}: {err:#}", event.hdr.pid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slow::test_event::event;

    #[test]
    fn records_of_other_versions_or_kinds_are_rejected() {
        let e = event("GET /a");
        // SAFETY: `RequestEvent` is plain data.
        let bytes = unsafe {
            std::slice::from_raw_parts((&raw const e).cast::<u8>(), size_of::<RequestEvent>())
        };
        // Aligned copy, as the ring buffer hands records out.
        let mut aligned = vec![0u64; bytes.len().div_ceil(8)];
        // SAFETY: the destination is at least as long as the source.
        let record = unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), aligned.as_mut_ptr().cast(), bytes.len());
            std::slice::from_raw_parts_mut(aligned.as_mut_ptr().cast::<u8>(), bytes.len())
        };
        let mut inbox = Inbox::default();
        receive(&mut inbox, record);
        assert_eq!((inbox.requests.len(), inbox.rejected), (1, 0));
        receive(&mut inbox, &record[..40]);
        assert_eq!(inbox.rejected, 1);
        record[0] = 99; // version
        receive(&mut inbox, record);
        assert_eq!(inbox.rejected, 2);
    }
}
