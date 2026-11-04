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
    /// The status the peer advertised for the path, if it sent one
    pub peer_status: Option<PathStatus>,
    /// Whether the path may carry application data at all: validated and not abandoned
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
    /// What the congestion controller estimates the path delivers, in bits per second, if it
    /// makes an estimate
    pub bandwidth: Option<u64>,
}

/// A [`PathScheduler`]'s decision for one path
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathChoice {
    /// The path
    pub id: PathId,
    /// Whether the path may carry stream data and datagrams that are not pinned to a path
    pub unpinned_data: bool,
}

/// Chooses the order paths are tried in, and which may carry data not pinned to a path
///
/// Called on every `poll_transmit` once the handshake is complete. Data pinned to a path,
/// control frames and congestion control are unaffected.
pub trait PathScheduler: Send + Sync + fmt::Debug {
    /// Fills the empty `choices` with a decision per path, in the order to try them
    ///
    /// Paths left out are tried last and carry only pinned data. Choices for unknown paths
    /// are ignored.
    ///
    /// `backlog` is what the connection has waiting to be sent that no path is bound to, in
    /// bytes: stream data, retransmissions included, and datagrams not pinned to a path.
    fn schedule(
        &mut self,
        now: Instant,
        backlog: u64,
        paths: &[PathSnapshot],
        choices: &mut Vec<PathChoice>,
    );
}

/// Builds a [`PathScheduler`] for each new connection
pub trait PathSchedulerFactory: Send + Sync + fmt::Debug {
    /// Builds the scheduler for a connection created at `now`
    fn build(&self, now: Instant) -> Box<dyn PathScheduler>;
}
