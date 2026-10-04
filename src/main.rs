//! Dynamic (subprocess) entrypoint for the pbs plugin.
//!
//! Serves this plugin over the orca socket via the typed `Plugin` builder: the
//! `pbs.` tool surface plus the `service` backend. The plugin is a `[[bin]]`,
//! owns no runtime, and reaches orca only through the socket.
plugin_toolkit::instrument::bootstrap!();
use pbs::PbsBackend;
use plugin_toolkit::plugin::Plugin;

// Force-link the `pbs.` #[orca_tool] modules so their inventory isn't
// dead-stripped at link time; nothing else in the bin references them.
#[allow(unused_imports)]
use pbs::{endpoint as _, enroll as _, tools as _};

fn main() -> plugin_toolkit::anyhow::Result<()> {
    Plugin::named("pbs")
        .version(env!("CARGO_PKG_VERSION"))
        .tools(["pbs."])
        .service(PbsBackend::new(pbs::PROVIDER))
        .serve()
}
