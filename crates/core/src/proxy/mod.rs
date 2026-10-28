//! The proxy itself: listeners, relay, routing, DNS and traffic counters.

pub mod dns;
pub mod dns_cache;
pub mod egress;
pub mod routing;
pub mod runtime;
pub mod stats;
