"""Internal Windows Host-owned Supervisor process entry point."""

from __future__ import annotations

import sys

import click


@click.command(hidden=True)
@click.option("--pipe-name", required=True)
def host_supervisor(pipe_name: str) -> None:
    """Run the Host-owned Broker; only the desktop Host starts this command."""
    from openjarvis.core.config import load_config
    from openjarvis.core.paths import get_config_dir

    if sys.platform != "win32":
        raise click.ClickException("Windows Host Supervisor is unavailable")
    config = load_config()
    if not config.agent_manager.enabled:
        raise click.ClickException("Host Supervisor requires Agent Manager")

    from openjarvis.agents.manager import AgentManager
    from openjarvis.control.host_supervisor_bootstrap import (
        HostSupervisorBootstrapService,
    )

    db_path = config.agent_manager.db_path or str(get_config_dir() / "agents.db")
    manager = AgentManager(db_path=db_path, clear_stale_running=False)
    service = None
    try:
        service = HostSupervisorBootstrapService(pipe_name, manager)
        service.run(sys.stdin.buffer)
    except Exception as exc:
        if service is None:
            manager.close()
        raise click.ClickException("Host Supervisor bootstrap failed closed") from exc


__all__ = ["host_supervisor"]
