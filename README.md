# ATLAS

**Autonomous Task, Learning & Assistance System**

![ATLAS workspace](assets/atlas-hero.png)

ATLAS is a Windows-first autonomous AI agent designed to plan, execute, observe,
verify, recover, and re-plan tasks while keeping final authorization inside
ATLAS.

## Safety boundary

ATLAS treats model, OSS, skill, memory, and worker output as untrusted
proposals. Mutating actions must pass the ATLAS Safety Authority with target
identity, session binding, nonce replay protection, exactly-once handling,
independent verification, and fail-closed error handling.

The current repository keeps the legacy engine as the default. browser-use and
Microsoft UFO integrations are limited to proposal, schema, worker, and fake
executor paths until their direct mutation and physical safety boundaries are
proven. No production OSS switch or physical Browser/GUI E2E is enabled by
default.

## Current capabilities

- Agent planning, execution, observation, verification, recovery, and replanning
- Browser and Windows-app integration boundaries
- Long-horizon execution and memory foundations
- Multi-model routing and MCP integration
- Privacy, egress, subprocess, and mutation-boundary enforcement
- Isolated browser-use and UFO worker validation

## Quick start

```bash
uv sync --extra dev
uv run jarvis
```

The CLI command remains `jarvis` for compatibility with the existing runtime;
the Python package namespace is currently `openjarvis`.

Run the test suite with:

```bash
uv run pytest tests/ -q
```

## Development

```bash
git clone https://github.com/naeishuu-collab/ATLAS.git
cd ATLAS
uv sync --extra dev
uv run pre-commit install
```

The expected development branch for the current integration work is
`opencode/cloud-privacy`.

## Repository layout

- `src/openjarvis/` — current Python runtime and compatibility namespace
- `tests/` — unit, safety, integration, and isolated-worker tests
- `frontend/` — real-time agent UI
- `desktop/` and `rust/` — desktop and native components
- `third-party/` — isolated OSS and security PoC material

## Project status

ATLAS is under active safety-focused development. Passing isolated tests or a
fake executor does not prove real browser, GUI, network, or OS-level sandbox
enforcement. Physical proof and production switching remain explicit approval
gates.

## License

This project is released under the [Apache 2.0 license](LICENSE).
