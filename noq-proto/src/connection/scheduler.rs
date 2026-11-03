//! Hook for choosing which multipath paths carry data that is not pinned to a path

use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use crate::{Duration, Instant};

use super::{PathId, PathStatus};

/// What a [`PathScheduler`] knows about one path when it decides
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct PathSnapshot {
    /// The path
    pub id: PathId,
    /// The status this endpoint advertised for the path
    pub status: PathStatus,
    /// Whether the path may carry application data at all: it has connection IDs, is not
    /// abandoned, and is validated (or the handshake is still in progress)
    pub can_send_data: bool,
    /// Smoothed round-trip time
    pub smoothed_rtt: Duration,
    /// Minimum round-trip time seen on the path
    pub min_rtt: Duration,
    /// Round-trip time variation
    pub rtt_variance: Duration,
    /// Congestion window, in bytes
    pub congestion_window: u64,
    /// Bytes sent on the path that are still in flight
    pub bytes_in_flight: u64,
    /// Current maximum UDP payload size on the path
    pub mtu: u16,
}

/// A [`PathScheduler`]'s decision for one path
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathChoice {
    /// The path
    pub id: PathId,
    /// Whether the path may carry stream data and datagrams that are not pinned to a path
    pub unpinned_data: bool,
}

/// Decides, on every [`Connection::poll_transmit`](super::Connection::poll_transmit), the
/// order in which paths are offered data and which of them may carry data that is not
/// pinned to a particular path
///
/// This replaces the default policy of trying paths in [`PathId`] order and sending
/// unpinned data only on [`PathStatus::Available`] paths (or on backup paths when no
/// available path is validated). It only applies once the handshake is complete.
///
/// Streams pinned with [`StreamAffinity::Sticky`](crate::StreamAffinity::Sticky),
/// acknowledgements, path validation and other control frames are not affected, and
/// congestion control, pacing and anti-amplification limits still apply to every path.
pub trait PathScheduler: Send + Sync + fmt::Debug {
    /// Fills `choices` with a decision per path, in the order the paths should be tried
    ///
    /// `choices` is empty when called. Paths that are left out are tried after all listed
    /// paths and carry no unpinned data. Choices for unknown paths are ignored.
    fn schedule(&mut self, now: Instant, paths: &[PathSnapshot], choices: &mut Vec<PathChoice>);
}

/// Builds a [`PathScheduler`] for each new connection
pub trait PathSchedulerFactory: Send + Sync + fmt::Debug {
    /// Builds the scheduler for a connection created at `now`
    fn build(&self, now: Instant) -> Box<dyn PathScheduler>;
}
