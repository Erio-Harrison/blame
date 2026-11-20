//! Where a tokio task that serves an HTTP/2 stream keeps the stream's id.
//!
//! hyper spawns one task per stream, and the task holds a reference to its
//! stream. Where in the task that is depends on how the compiler laid the
//! future out, so it is found from the tasks themselves: the kernel side
//! sends the first bytes of every task a connection's task spawns, and a
//! position is kept only while, at every spawn, what it holds
//!
//! - is odd (a stream the client opened),
//! - is a stream the frame parser saw the client open on that connection,
//! - is greater than what it held at the same connection's previous spawn.
//!
//! A position is ruled out only by a task in which another position does
//! hold an id like that. A task in which none does says nothing about the
//! positions: the opening of its stream may not have been seen (its record
//! was dropped). Positions that survive are trusted once each has shown enough
//! different ids. Nothing else in a task behaves like that; a kind of task
//! in which no position holds one, many times in a row, is given up on.

use std::collections::{HashMap, HashSet};

use blame_common::{TASK_SAMPLE_LEN, TaskSampleEvent};

/// Different ids a position must have shown before it is trusted.
const IDS_NEEDED: usize = 8;
/// Spawns looked at before a kind of task is given up on.
const SAMPLES_MAX: u32 = 256;
/// Spawns in a row in which no position holds a stream id, before a kind of
/// task is taken for one that does not keep one.
const MISSES_MAX: u32 = 8;

/// What was found for one kind of task of one process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found {
    /// Two positions that hold the id (the same one twice if there is only one).
    At(u16, u16),
    /// No position holds a stream id: not a task that serves streams.
    Nowhere,
}

#[derive(Default)]
struct Kind {
    samples: u32,
    /// Positions still standing; `None` before the first sample.
    standing: Option<Vec<u16>>,
    /// (connection task, position) -> the id it held last.
    last: HashMap<(u64, u16), u32>,
    seen: HashMap<u16, HashSet<u32>>,
    /// Spawns in a row in which no position held.
    misses: u32,
    done: bool,
}

#[derive(Default)]
pub struct Calibrator {
    kinds: HashMap<(u32, u64), Kind>,
}

impl Calibrator {
    /// Look at one new task. `opened` says whether the client opened a
    /// stream on a connection. Returns the verdict once, when it is reached.
    pub fn sample(
        &mut self,
        event: &TaskSampleEvent,
        opened: impl Fn(u64, u32) -> bool,
    ) -> Option<Found> {
        let kind = self.kinds.entry((event.hdr.pid, event.vtable)).or_default();
        if kind.done {
            return None;
        }
        kind.samples += 1;
        let standing = kind
            .standing
            .get_or_insert_with(|| (0..TASK_SAMPLE_LEN as u16).step_by(4).collect());
        let value_at = |at: u16| {
            let at = usize::from(at);
            u32::from_ne_bytes(event.mem[at..at + 4].try_into().expect("four bytes"))
        };
        let holding: Vec<u16> = standing
            .iter()
            .copied()
            .filter(|&at| {
                let value = value_at(at);
                let last = kind.last.get(&(event.parent, at)).copied().unwrap_or(0);
                value & 1 == 1 && value > last && opened(event.conn, value)
            })
            .collect();
        if holding.is_empty() {
            kind.misses += 1;
        } else {
            kind.misses = 0;
            for &at in &holding {
                let value = value_at(at);
                kind.last.insert((event.parent, at), value);
                kind.seen.entry(at).or_default().insert(value);
            }
            *standing = holding;
        }
        let verdict = if kind.misses >= MISSES_MAX {
            Some(Found::Nowhere)
        } else if standing
            .iter()
            .all(|at| kind.seen.get(at).is_some_and(|ids| ids.len() >= IDS_NEEDED))
        {
            Some(Found::At(
                standing[0],
                *standing.get(1).unwrap_or(&standing[0]),
            ))
        } else if kind.samples >= SAMPLES_MAX {
            Some(Found::Nowhere)
        } else {
            None
        };
        if verdict.is_some() {
            *kind = Kind {
                done: true,
                ..Kind::default()
            };
        }
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blame_common::EventHeader;

    fn task(parent: u64, sid: u32, noise: u32) -> TaskSampleEvent {
        // SAFETY: plain integers and bytes; all zeroes is a valid value.
        let mut event: TaskSampleEvent = unsafe { std::mem::zeroed() };
        let hdr: EventHeader = unsafe { std::mem::zeroed() };
        event.hdr = hdr;
        event.hdr.pid = 42;
        event.vtable = 0x1000;
        event.conn = parent + 100;
        event.parent = parent;
        for (at, value) in [
            (316, sid),
            (380, sid),
            (40, 1),
            (44, noise),
            (48, noise | 1),
            (52, 2 * sid),
        ] {
            event.mem[at..at + 4].copy_from_slice(&value.to_ne_bytes());
        }
        event
    }

    #[test]
    fn the_positions_that_always_hold_the_stream_id_are_found() {
        let mut calibrator = Calibrator::default();
        let opened = |_conn: u64, sid: u32| sid < 1000;
        let mut verdict = None;
        let mut spawns = 0;
        // Two connections, ids going up on each, some refused in between.
        for (parent, sid) in [
            (1, 1),
            (2, 1),
            (1, 3),
            (1, 9),
            (2, 3),
            (1, 11),
            (1, 13),
            (2, 5),
            (1, 21),
            (1, 23),
            (1, 25),
            (1, 27),
        ] {
            spawns += 1;
            verdict = calibrator.sample(&task(parent, sid, spawns * 7919), opened);
            if verdict.is_some() {
                break;
            }
        }
        assert_eq!(verdict, Some(Found::At(316, 380)));
        // Eight different ids were needed, no more.
        assert_eq!(spawns, 10);
        // Decided: later samples of this kind say nothing.
        assert_eq!(calibrator.sample(&task(1, 99, 0), opened), None);
    }

    #[test]
    fn a_kind_of_task_without_a_stream_id_is_given_up_on() {
        let mut calibrator = Calibrator::default();
        // Nothing in it is a stream the client opened.
        for i in 1..MISSES_MAX {
            assert_eq!(
                calibrator.sample(&task(1, 5 + 2 * i, 12345), |_, _| false),
                None
            );
        }
        let verdict = calibrator.sample(&task(1, 99, 12345), |_, _| false);
        assert_eq!(verdict, Some(Found::Nowhere));
    }

    #[test]
    fn a_task_whose_stream_was_not_seen_opening_rules_nothing_out() {
        let mut calibrator = Calibrator::default();
        // The first one's opening went by unseen (seen: ids from 3 on).
        let opened = |_conn: u64, sid: u32| (3..1000).contains(&sid);
        let mut verdict = None;
        for (n, sid) in [1, 3, 5, 7, 9, 11, 13, 15, 17].into_iter().enumerate() {
            verdict = calibrator.sample(&task(1, sid, n as u32 * 7919), opened);
        }
        assert_eq!(verdict, Some(Found::At(316, 380)));
    }
}
