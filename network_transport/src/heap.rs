//! OutboundHeap — shared priority queue for network frames.
//!
//! Any engine pushes frames directly (std::sync::Mutex, fast path).
//! The network writer task drains the heap, highest priority first.

use crate::Frame;
use std::collections::BinaryHeap;
use std::cmp::Reverse;
use std::sync::Mutex;
use std::task::Waker;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Realtime = 0,
    Normal = 1,
    Bulk = 2,
}

struct Entry {
    priority: Priority,
    seq: u64,
    frame: Frame,
}

impl PartialEq for Entry { fn eq(&self, o: &Self) -> bool { self.seq == o.seq } }
impl Eq for Entry {}
impl PartialOrd for Entry {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(o)) }
}
impl Ord for Entry {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (self.priority as u8, self.seq).cmp(&(o.priority as u8, o.seq))
    }
}

pub struct OutboundHeap {
    heap: Mutex<BinaryHeap<Reverse<Entry>>>,
    seq: Mutex<u64>,
    waker: Mutex<Option<Waker>>,
}

impl OutboundHeap {
    pub fn new() -> Self {
        Self {
            heap: Mutex::new(BinaryHeap::new()),
            seq: Mutex::new(0),
            waker: Mutex::new(None),
        }
    }

    /// Push a frame. Returns false if mutex poisoned (shouldn't happen).
    pub fn push(&self, priority: Priority, frame: Frame) -> bool {
        let seq = {
            let mut s = match self.seq.lock() { Ok(s) => s, Err(_) => return false };
            *s += 1;
            *s
        };
        let mut heap = match self.heap.lock() { Ok(h) => h, Err(_) => return false };
        heap.push(Reverse(Entry { priority, seq, frame }));
        // Wake the writer
        if let Ok(w) = self.waker.lock() {
            if let Some(waker) = w.as_ref() {
                waker.wake_by_ref();
            }
        }
        true
    }

    /// Push raw encoded bytes with a given priority.
    pub fn push_raw(&self, priority: Priority, data: Vec<u8>) -> bool {
        // Decode the frame so it can be stored properly
        if let Some((frame, _)) = Frame::decode(&data) {
            self.push(priority, frame)
        } else {
            false
        }
    }

    /// Drain all frames, highest priority first.
    pub fn drain(&self) -> Vec<Frame> {
        let mut heap = match self.heap.lock() { Ok(h) => h, Err(_) => return vec![] };
        let mut frames = Vec::with_capacity(heap.len());
        while let Some(Reverse(entry)) = heap.pop() {
            frames.push(entry.frame);
        }
        frames
    }

    /// Pop one frame (highest priority).
    pub fn pop(&self) -> Option<Frame> {
        let mut heap = match self.heap.lock() { Ok(h) => h, Err(_) => return None };
        heap.pop().map(|Reverse(e)| e.frame)
    }

    /// Is the heap empty?
    pub fn is_empty(&self) -> bool {
        match self.heap.lock() { Ok(h) => h.is_empty(), Err(_) => true }
    }

    /// Register the writer's waker so push() can wake it.
    pub fn register_waker(&self, waker: &Waker) {
        if let Ok(mut w) = self.waker.lock() {
            *w = Some(waker.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    #[test]
    fn push_and_drain_priority_order() {
        let heap = OutboundHeap::new();
        let f1 = Frame::jsonl(endpoint(1, SVC_NODE), endpoint(2, SVC_NODE), "bulk");
        let f2 = Frame::jsonl(endpoint(1, SVC_NODE), endpoint(2, SVC_NODE), "realtime");
        let f3 = Frame::jsonl(endpoint(1, SVC_NODE), endpoint(2, SVC_NODE), "normal");

        heap.push(Priority::Bulk, f1);
        heap.push(Priority::Realtime, f2);
        heap.push(Priority::Normal, f3);

        let frames = heap.drain();
        assert_eq!(frames.len(), 3);
        assert_eq!(std::str::from_utf8(&frames[0].payload).unwrap(), "realtime");
        assert_eq!(std::str::from_utf8(&frames[1].payload).unwrap(), "normal");
        assert_eq!(std::str::from_utf8(&frames[2].payload).unwrap(), "bulk");
    }

    #[test]
    fn push_returns_true() {
        let heap = OutboundHeap::new();
        let f = Frame::jsonl(endpoint(1, SVC_NODE), endpoint(2, SVC_NODE), "test");
        assert!(heap.push(Priority::Normal, f));
    }

    #[test]
    fn empty_drain() {
        let heap = OutboundHeap::new();
        assert!(heap.drain().is_empty());
        assert!(heap.is_empty());
    }
}
