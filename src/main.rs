//! Dynamic (subprocess) entrypoint for the pbs plugin.
//!
//! Serves this plugin over the orca socket via the typed `Plugin` builder: the
//! `pbs.` tool surface, the `service` backend and the `pbs-config` backup
//! kind. The plugin is a `[[bin]]`, owns no runtime, and reaches orca only
//! through the socket.
plugin_toolkit::instrument::bootstrap!();
use pbs::PbsBackend;
use plugin_toolkit::plugin::Plugin;

// Force-link the `pbs.` #[orca_tool] modules so their inventory isn't
// dead-stripped at link time; nothing else in the bin references them.
#[allow(unused_imports)]
use pbs::{config_backup as _, endpoint as _, enroll as _, groups as _, jobs as _, tools as _};

fn main() -> plugin_toolkit::anyhow::Result<()> {
    Plugin::named("pbs")
        .version(env!("CARGO_PKG_VERSION"))
        .tools(["pbs."])
        .service(PbsBackend::new(pbs::PROVIDER))
        .backend(
            pbs::config_backup::backend_def(),
            Box::new(pbs::config_backup::dispatcher),
        )
        .serve()
}
