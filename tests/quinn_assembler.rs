// Run the vendored assembler's own unit/security regressions under the main
// project's normal `cargo test --all-targets`, including our backlog regression.
#![allow(dead_code)]

// Preserve upstream's Rust 2021 formatting and nested-if style verbatim.
#[rustfmt::skip]
#[allow(clippy::collapsible_if)]
#[path = "../vendor/quinn-proto/src/range_set/btree_range_set.rs"]
mod btree_range_set;
mod range_set {
    pub(crate) use super::btree_range_set::RangeSet;
}

#[rustfmt::skip]
#[path = "../vendor/quinn-proto/src/connection/assembler.rs"]
mod assembler;
