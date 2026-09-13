# endpointsweep (npm pointer package)

**EndpointSweep is a Python tool.** This npm package exists only so that
`npx endpointsweep` points you at the real thing, and so the name is not
available to anyone else.

## Install

```sh
pipx install endpointsweep     # recommended
pip install endpointsweep
```

## Use

```sh
endpointsweep scan                        # audit this machine
endpointsweep merge collected/ -o fleet.json
endpointsweep report fleet.json -o fleet.md
esweep --help                             # short alias
```

Find every MCP server and AI agent on your endpoint fleet: dependency-free
collectors for macOS, Linux and Windows run under EDR/MDM, and a central
analyzer audits them against a published 8-vector risk rubric.

Source, docs and issues: <https://github.com/harish-ravichandra/endpointsweep>

MIT licensed.
