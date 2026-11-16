use alloc::{collections::VecDeque, vec::Vec};
use core::num::NonZeroU64;

use bytes::Bytes;
use thiserror::Error;
use tracing::{debug, trace};

use super::{Connection, PathStatsMap};
use crate::{
    FrameStats, FxHashMap, PathId, TransportError,
    connection::PacketBuilder,
    frame::{Datagram, FrameStruct},
};

/// API to control datagram traffic
pub struct Datagrams<'a> {
    pub(super) conn: &'a mut Connection,
}

impl Datagrams<'_> {
    /// Queue an unreliable, unordered datagram for immediate transmission
    ///
    /// If `drop` is true, previously queued datagrams which are still unsent may be discarded to
    /// make space for this datagram, in order of oldest to newest. If `drop` is false, and there
    /// isn't enough space due to previously queued datagrams, this function will return
    /// `SendDatagramError::Blocked`. `Event::DatagramsUnblocked` will be emitted once datagrams
    /// have been sent.
    ///
    /// Returns `Err` iff a `len`-byte datagram cannot currently be sent.
    pub fn send(&mut self, data: Bytes, drop: bool) -> Result<(), SendDatagramError> {
        self.queue(None, data, drop, false, None)
    }

    /// Queue an unreliable, unordered datagram to be sent on `path` only, whatever its status
    ///
    /// Each path has its own send buffer, to which `drop` applies as in [`Self::send`].
    /// Datagrams still queued when the path is discarded are dropped.
    pub fn send_on_path(
        &mut self,
        path: PathId,
        data: Bytes,
        drop: bool,
    ) -> Result<(), SendDatagramError> {
        self.queue_on_path(path, data, drop, false, None)
    }

    /// Queue an unreliable, unordered datagram to be sent on `path` only, ahead of its
    /// datagrams queued with [`Self::send_on_path`] and of stream data
    ///
    /// For light traffic that must not wait behind bulk, such as calls, games or DNS. It shares
    /// the path's send buffer, which drops other datagrams first to make room.
    pub fn send_urgent_on_path(
        &mut self,
        path: PathId,
        data: Bytes,
    ) -> Result<(), SendDatagramError> {
        self.queue_on_path(path, data, true, true, None)
    }

    /// Queue `data` on `path` as the original of a datagram whose copies go on other paths
    /// with [`Self::send_copy_on_path`]
    ///
    /// It is never cancelled, but once a packet carrying it is acknowledged, the copies of
    /// `group` still queued are dropped. Otherwise as [`Self::send_urgent_on_path`] if `urgent`,
    /// or [`Self::send_on_path`] dropping older datagrams to make room.
    pub fn send_original_on_path(
        &mut self,
        path: PathId,
        data: Bytes,
        group: NonZeroU64,
        urgent: bool,
    ) -> Result<(), SendDatagramError> {
        let group = Group {
            id: group,
            copy: false,
        };
        self.queue_on_path(path, data, true, urgent, Some(group))
    }

    /// Queue `data` on `path` as a copy of a datagram sent on several paths, dropped unsent
    /// once a packet carrying its original or another copy is acknowledged
    ///
    /// The original and its copies share `group`. Groups should increase in the order they are
    /// queued, as cancelling stops at the first larger group in a path's queue. Otherwise as
    /// [`Self::send_original_on_path`].
    pub fn send_copy_on_path(
        &mut self,
        path: PathId,
        data: Bytes,
        group: NonZeroU64,
        urgent: bool,
    ) -> Result<(), SendDatagramError> {
        let group = Group {
            id: group,
            copy: true,
        };
        self.queue_on_path(path, data, true, urgent, Some(group))
    }

    fn queue_on_path(
        &mut self,
        path: PathId,
        data: Bytes,
        drop: bool,
        urgent: bool,
        group: Option<Group>,
    ) -> Result<(), SendDatagramError> {
        if !self.conn.paths.contains_key(&path) || self.conn.abandoned_paths.contains(&path) {
            return Err(SendDatagramError::PathClosed);
        }
        self.queue(Some(path), data, drop, urgent, group)
    }

    fn queue(
        &mut self,
        path: Option<PathId>,
        data: Bytes,
        drop: bool,
        urgent: bool,
        group: Option<Group>,
    ) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        let send_buffer_size = self.conn.config.datagram_send_buffer_size;
        if data.len() > Ord::min(max, send_buffer_size) {
            return Err(SendDatagramError::TooLarge);
        }
        let datagrams = &mut self.conn.datagrams;
        let buffer = match path {
            None => &mut datagrams.outgoing,
            Some(path) => datagrams.outgoing_on_path.entry(path).or_default(),
        };
        if drop {
            buffer.make_space_for(data.len(), send_buffer_size);
        } else if !buffer.has_send_buffer_space(data.len(), send_buffer_size) {
            datagrams.send_blocked = true;
            return Err(SendDatagramError::Blocked(data));
        }
        buffer.push(Datagram { data }, group, urgent);
        Ok(())
    }

    /// Queue many unreliable, unordered datagrams for transmission in a single call.
    ///
    /// This is the batch analogue of [`Self::send`], avoiding repeated connection checks.
    ///
    /// The batch is rejected atomically with the [`TooLarge`] error if any datagram
    /// in the batch is too large.
    ///
    /// `drop` selects the backpressure behaviour, matching [`Self::send`]:
    ///
    /// - `drop = true` drops the oldest queued datagrams to make room, so every element is queued
    ///   and `Ok(datagrams.len())` is returned.
    /// - `drop = false` queues elements until the send buffer is full, then stops and returns
    ///   `Ok(n)` for the `n` elements queued. The remaining elements are the caller's to retry once
    ///   space frees up.
    ///
    /// Returns `Err` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// [`TooLarge`]: SendDatagramError::TooLarge
    pub fn send_many(
        &mut self,
        datagrams: &[Bytes],
        drop: bool,
    ) -> Result<usize, SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        let send_buffer_size = self.conn.config.datagram_send_buffer_size;
        if datagrams
            .iter()
            .any(|data| data.len() > Ord::min(max, send_buffer_size))
        {
            return Err(SendDatagramError::TooLarge);
        }

        let mut queued = 0usize;
        let state = &mut self.conn.datagrams;
        for data in datagrams {
            if drop {
                state.outgoing.make_space_for(data.len(), send_buffer_size);
            } else if !state
                .outgoing
                .has_send_buffer_space(data.len(), send_buffer_size)
            {
                state.send_blocked = true;
                break;
            }
            state.outgoing.push_back(Datagram { data: data.clone() });
            queued += 1;
        }

        Ok(queued)
    }

    /// Compute the maximum size of datagrams that may be passed to `send_datagram`
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    ///
    /// When multipath is enabled, this is calculated using the smallest MTU across all
    /// available paths.
    pub fn max_size(&self) -> Option<usize> {
        // We use the conservative overhead bound for any packet number, reducing the budget by at
        // most 3 bytes, so that PN size fluctuations don't cause users sending maximum-size
        // datagrams to suffer avoidable packet loss.
        let max_size = self.conn.current_mtu() as usize
            - self.conn.predict_1rtt_overhead_no_pn()
            - Datagram::SIZE_BOUND;
        let limit = self
            .conn
            .peer_params
            .max_datagram_frame_size?
            .into_inner()
            .saturating_sub(Datagram::SIZE_BOUND as u64);
        Some(limit.min(max_size as u64) as usize)
    }

    /// Receive an unreliable, unordered datagram
    pub fn recv(&mut self) -> Option<Bytes> {
        self.conn.datagrams.recv()
    }

    /// Drain up to `out.len()` buffered datagrams into `out`, in arrival order.
    ///
    /// This is the batch analogue of [`Self::recv`]: a single call takes many
    /// datagrams at once. `out` is filled from the front and overwritten in place;
    /// pass a slice of empty `Bytes` sized to the batch you want. Returns the number
    /// of datagrams written, which may be less than `out.len()` if fewer are buffered
    /// (0 if none). Any remaining datagrams stay queued for the next call.
    pub fn recv_many(&mut self, out: &mut [Bytes]) -> usize {
        self.conn.datagrams.recv_many(out)
    }

    /// Bytes available in the outgoing datagram buffer
    ///
    /// When greater than zero, [`send`](Self::send)ing a datagram of at most this size is
    /// guaranteed not to cause older datagrams to be dropped.
    pub fn send_buffer_space(&self) -> usize {
        self.conn
            .config
            .datagram_send_buffer_size
            .saturating_sub(self.conn.datagrams.outgoing.payload_bytes)
            .saturating_sub(size_of::<Datagram>())
    }

    /// Payload bytes queued with [`Self::send_on_path`] and not yet sent on `path`
    pub fn queued_on_path(&self, path: PathId) -> usize {
        self.conn
            .datagrams
            .outgoing_on_path
            .get(&path)
            .map_or(0, |buffer| buffer.payload_bytes)
    }
}

#[derive(Default)]
pub(super) struct DatagramState {
    pub(super) incoming: DatagramBuffer,
    pub(super) outgoing: DatagramBuffer,
    pub(super) outgoing_on_path: FxHashMap<PathId, DatagramBuffer>,
    pub(super) send_blocked: bool,
    /// Copy groups acknowledged since their queued copies were last cancelled
    acked_copies: Vec<u64>,
}

impl DatagramState {
    pub(super) fn received(
        &mut self,
        datagram: Datagram,
        window: &Option<usize>,
    ) -> Result<bool, TransportError> {
        let window = match window {
            None => {
                return Err(TransportError::PROTOCOL_VIOLATION(
                    "unexpected DATAGRAM frame",
                ));
            }
            Some(x) => *x,
        };

        let size_with_overhead = datagram.data.len() + size_of::<Datagram>();

        if size_with_overhead > window {
            return Err(TransportError::PROTOCOL_VIOLATION("oversized datagram"));
        }

        let was_empty = self.incoming.is_empty();
        while self.incoming.memory_used() + size_with_overhead > window {
            debug!("dropping stale datagram");
            self.recv();
        }

        self.incoming.push_back(datagram);
        Ok(was_empty)
    }

    /// Discard outgoing datagrams with a payload larger than `max_payload` bytes
    ///
    /// Returns whether any datagrams were dropped.
    ///
    /// Used to ensure that reductions in MTU don't get us stuck in a state where we have a datagram
    /// queued but can't send it.
    pub(super) fn drop_oversized(&mut self, max_payload: usize) -> bool {
        let mut dropped_any = self.outgoing.drop_oversized(max_payload);
        for buffer in self.outgoing_on_path.values_mut() {
            dropped_any |= buffer.drop_oversized(max_payload);
        }
        dropped_any
    }

    /// Attempt to write a datagram frame for `path` into `buf`, preferring one bound to it
    ///
    /// Returns whether a frame was written.
    pub(super) fn write<'a, 'b>(
        &mut self,
        path: PathId,
        unpinned: bool,
        buf: &mut PacketBuilder<'a, 'b>,
        stat: &mut FrameStats,
    ) -> bool {
        if let Some(buffer) = self.outgoing_on_path.get_mut(&path)
            && buffer.write(buf, stat)
        {
            return true;
        }
        unpinned && self.outgoing.write(buf, stat)
    }

    /// Whether `path` has urgent datagrams waiting, which go before stream data
    pub(super) fn has_urgent(&self, path: PathId) -> bool {
        self.outgoing_on_path
            .get(&path)
            .is_some_and(|buffer| !buffer.urgent.is_empty())
    }

    pub(super) fn can_send_on_path(&self, path: PathId, max_size: usize) -> bool {
        self.outgoing_on_path
            .get(&path)
            .is_some_and(|buffer| buffer.can_send_1rtt(max_size))
    }

    pub(super) fn has_outgoing(&self, path: PathId) -> bool {
        !self.outgoing.is_empty()
            || self
                .outgoing_on_path
                .get(&path)
                .is_some_and(|buffer| !buffer.is_empty())
    }

    /// Notes that a packet carrying a copy of `group` was acknowledged
    pub(super) fn copy_acked(&mut self, group: u64) {
        self.acked_copies.push(group);
    }

    /// Drops the queued copies of the groups acknowledged since the last call
    pub(super) fn cancel_acked_copies(&mut self, stats: &mut PathStatsMap) {
        if self.acked_copies.is_empty() {
            return;
        }
        self.acked_copies.sort_unstable();
        self.acked_copies.dedup();
        for (&path, buffer) in &mut self.outgoing_on_path {
            let (copies, bytes) = buffer.cancel(&self.acked_copies);
            if copies > 0 {
                trace!(%path, copies, "cancelled copies already delivered");
                let stats = stats.get_mut(path);
                stats.cancelled_copies += copies;
                stats.cancelled_copy_bytes += bytes;
            }
        }
        self.acked_copies.clear();
    }

    pub(super) fn discard_path(&mut self, path: PathId) {
        if let Some(buffer) = self.outgoing_on_path.remove(&path) {
            trace!(%path, count = buffer.len(), "dropping datagrams bound to discarded path");
        }
    }

    pub(super) fn recv(&mut self) -> Option<Bytes> {
        let x = self.incoming.pop_front()?.datagram.data;
        Some(x)
    }

    /// Drain up to `out.len()` buffered datagrams into `out`, in arrival order.
    ///
    /// Returns the number of datagrams written into `out` (which may be less than
    /// `out.len()` if fewer are buffered). Remaining datagrams stay queued.
    pub(super) fn recv_many(&mut self, out: &mut [Bytes]) -> usize {
        let n = out.len().min(self.incoming.len());
        for (i, d) in self.incoming.drain_front(n).enumerate() {
            out[i] = d.datagram.data;
        }
        n
    }
}

#[derive(Default)]
pub(super) struct DatagramBuffer {
    /// Sent before `queue`
    urgent: VecDeque<Queued>,
    queue: VecDeque<Queued>,
    payload_bytes: usize,
    /// How many of the datagrams in `urgent` and in `queue` are copies
    copies: [usize; 2],
}

/// A datagram waiting in a [`DatagramBuffer`]
struct Queued {
    datagram: Datagram,
    group: Option<Group>,
}

impl Queued {
    fn is_copy(&self) -> bool {
        self.group.is_some_and(|group| group.copy)
    }
}

/// The group shared by a datagram's original and its copies on other paths
#[derive(Clone, Copy)]
struct Group {
    id: NonZeroU64,
    copy: bool,
}

impl DatagramBuffer {
    fn push(&mut self, datagram: Datagram, group: Option<Group>, urgent: bool) {
        self.payload_bytes += datagram.data.len();
        self.copies[!urgent as usize] += group.is_some_and(|group| group.copy) as usize;
        let queued = Queued { datagram, group };
        match urgent {
            true => self.urgent.push_back(queued),
            false => self.queue.push_back(queued),
        }
    }

    fn push_back(&mut self, datagram: Datagram) {
        self.push(datagram, None, false);
    }

    #[cfg(test)]
    fn push_urgent(&mut self, datagram: Datagram) {
        self.push(datagram, None, true);
    }

    /// Removes the next datagram to send
    fn pop_front(&mut self) -> Option<Queued> {
        let urgent = !self.urgent.is_empty();
        let queued = match urgent {
            true => self.urgent.pop_front(),
            false => self.queue.pop_front(),
        }?;
        self.forget(&queued, urgent);
        Some(queued)
    }

    /// Accounts for `queued` having left the buffer
    fn forget(&mut self, queued: &Queued, urgent: bool) {
        self.payload_bytes -= queued.datagram.data.len();
        self.copies[!urgent as usize] -= queued.is_copy() as usize;
    }

    fn front(&self) -> Option<&Datagram> {
        self.urgent
            .front()
            .or_else(|| self.queue.front())
            .map(|queued| &queued.datagram)
    }

    /// Payload bytes queued and not yet sent
    pub(super) fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    fn memory_used(&self) -> usize {
        self.payload_bytes
            .saturating_add(self.len() * size_of::<Datagram>())
    }

    /// Drops the oldest datagrams, urgent ones last, until `datagram_len` more bytes fit
    fn make_space_for(&mut self, datagram_len: usize, send_buffer_size: usize) {
        while !self.has_send_buffer_space(datagram_len, send_buffer_size) {
            let urgent = self.queue.is_empty();
            let Some(prev) = (match urgent {
                true => self.urgent.pop_front(),
                false => self.queue.pop_front(),
            }) else {
                break;
            };
            self.forget(&prev, urgent);
            trace!(len = prev.datagram.data.len(), "dropping outgoing datagram");
        }
    }

    fn has_send_buffer_space(&self, datagram_len: usize, send_buffer_size: usize) -> bool {
        let Some(total) = self.memory_used().checked_add(datagram_len) else {
            return false;
        };

        total <= send_buffer_size
    }

    fn drop_oversized(&mut self, max_payload: usize) -> bool {
        let mut dropped_any = false;
        let payload_bytes = &mut self.payload_bytes;
        let [urgent_copies, queue_copies] = &mut self.copies;
        for (queue, copies) in [
            (&mut self.urgent, urgent_copies),
            (&mut self.queue, queue_copies),
        ] {
            queue.retain(|queued| {
                let len = queued.datagram.data.len();
                let result = len < max_payload;
                if !result {
                    trace!(
                        "dropping {} byte datagram violating {} byte limit",
                        len, max_payload
                    );
                    *payload_bytes -= len;
                    *copies -= queued.is_copy() as usize;
                    dropped_any = true;
                }
                result
            });
        }
        dropped_any
    }

    /// Drops the queued copies of the `acked` groups, which are sorted
    ///
    /// Returns how many copies and payload bytes were dropped.
    fn cancel(&mut self, acked: &[u64]) -> (u64, u64) {
        let (mut cancelled, mut bytes) = (0, 0);
        let Some(&last) = acked.last() else {
            return (0, 0);
        };
        let [urgent_copies, queue_copies] = &mut self.copies;
        for (queue, copies) in [
            (&mut self.urgent, urgent_copies),
            (&mut self.queue, queue_copies),
        ] {
            let mut unseen = *copies;
            let mut index = 0;
            while unseen > 0 && index < queue.len() {
                let queued = &queue[index];
                let Some(group) = queued.group.filter(|_| queued.is_copy()) else {
                    index += 1;
                    continue;
                };
                let group = group.id.get();
                if group > last {
                    break;
                }
                unseen -= 1;
                if acked.binary_search(&group).is_err() {
                    index += 1;
                    continue;
                }
                let Some(queued) = queue.remove(index) else {
                    break;
                };
                let len = queued.datagram.data.len();
                self.payload_bytes -= len;
                *copies -= 1;
                cancelled += 1;
                bytes += len as u64;
            }
        }
        (cancelled, bytes)
    }

    /// Attempt to write the next datagram frame into `buf`, consuming it
    ///
    /// Returns whether a frame was written.
    fn write<'a, 'b>(&mut self, buf: &mut PacketBuilder<'a, 'b>, stat: &mut FrameStats) -> bool {
        // Future work: we could be more clever about cramming small datagrams into
        // mostly-full packets when a larger one is queued first
        if self
            .front()
            .is_none_or(|datagram| buf.frame_space_remaining() < datagram.size(true))
        {
            return false;
        }
        let Some(queued) = self.pop_front() else {
            return false;
        };
        if let Some(group) = queued.group {
            buf.record_copy(group.id);
        }
        buf.write_frame(queued.datagram, stat);
        true
    }

    pub(super) fn can_send_1rtt(&self, max_size: usize) -> bool {
        self.front().is_some_and(|x| x.size(true) <= max_size)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.urgent.is_empty() && self.queue.is_empty()
    }

    fn len(&self) -> usize {
        self.urgent.len() + self.queue.len()
    }

    /// Removes and returns the first `n` datagrams, in arrival order.
    fn drain_front(&mut self, n: usize) -> impl Iterator<Item = Queued> + '_ {
        let payload_bytes = &mut self.payload_bytes;
        self.queue.drain(..n).inspect(|queued| {
            *payload_bytes -= queued.datagram.data.len();
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_space_for_accounts_for_new_datagram() {
        let mut state = DatagramState::default();
        state.outgoing.push_back(Datagram {
            data: Bytes::from_static(&[0; 7]),
        });
        state.outgoing.push_back(Datagram {
            data: Bytes::from_static(&[0; 2]),
        });

        state
            .outgoing
            .make_space_for(4, 10 + 2 * size_of::<Datagram>());

        assert_eq!(state.outgoing.queue.len(), 1);
        assert_eq!(state.outgoing.queue[0].datagram.data.len(), 2);
        assert_eq!(state.outgoing.payload_bytes, 2);
    }

    fn datagram(len: usize) -> Datagram {
        Datagram {
            data: Bytes::from(alloc::vec![0; len]),
        }
    }

    #[test]
    fn urgent_datagrams_go_first_and_are_dropped_last() {
        let mut buffer = DatagramBuffer::default();
        buffer.push_back(datagram(1));
        buffer.push_back(datagram(2));
        buffer.push_urgent(datagram(3));
        assert_eq!(buffer.payload_bytes(), 6);
        assert_eq!(buffer.front().map(|d| d.data.len()), Some(3));

        // Room for one more 3-byte datagram costs both bulk ones, not the urgent one.
        buffer.make_space_for(3, 6 + 2 * size_of::<Datagram>());
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer.pop_front().map(|d| d.datagram.data.len()), Some(3));
        assert!(buffer.is_empty());
        assert_eq!(buffer.payload_bytes(), 0);
    }

    #[test]
    fn acknowledged_groups_lose_their_queued_copies() {
        let mut buffer = DatagramBuffer::default();
        let copy = |id| NonZeroU64::new(id).map(|id| Group { id, copy: true });
        buffer.push(datagram(1), copy(1), false);
        buffer.push(datagram(2), None, false);
        buffer.push(datagram(3), copy(2), false);
        let original = NonZeroU64::new(3).map(|id| Group { id, copy: false });
        buffer.push(datagram(6), original, false);
        buffer.push(datagram(4), copy(3), true);
        buffer.push(datagram(5), copy(5), false);

        assert_eq!(buffer.cancel(&[1, 3, 4]), (2, 5));
        assert_eq!(buffer.payload_bytes(), 16);
        assert_eq!(buffer.copies, [0, 2]);
        let left: Vec<usize> = core::iter::from_fn(|| buffer.pop_front())
            .map(|queued| queued.datagram.data.len())
            .collect();
        assert_eq!(left, [2, 3, 6, 5]);
        assert_eq!(buffer.copies, [0, 0]);
    }

    #[test]
    fn make_space_for_handles_overflowing_capacity_check() {
        let mut state = DatagramState::default();
        state.outgoing.push_back(Datagram {
            data: Bytes::from_static(&[0]),
        });
        state.outgoing.payload_bytes = usize::MAX - 1;

        state.outgoing.make_space_for(2, usize::MAX);

        assert!(state.outgoing.is_empty());
        assert_eq!(state.outgoing.payload_bytes, usize::MAX - 2);
    }

    #[test]
    fn empty_frame_flood_limit() {
        let mut state = DatagramState::default();
        let datagram = Datagram { data: Bytes::new() };
        let window = 100;
        loop {
            let initial_count = state.incoming.queue.len();
            state.received(datagram.clone(), &Some(window)).unwrap();
            assert!(state.incoming.queue.len() * size_of::<Datagram>() <= window);
            if state.incoming.queue.len() == initial_count {
                // Datagrams are getting dropped
                break;
            }
        }
    }
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error("datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    #[error("datagram too large")]
    TooLarge,
    /// Send would block
    #[error("datagram send blocked")]
    Blocked(Bytes),
    /// The path the datagram was bound to is closed or unknown
    #[error("path closed")]
    PathClosed,
}
