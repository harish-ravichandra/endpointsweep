#!/usr/bin/env node
// EndpointSweep is distributed on PyPI. This npm entry exists so that
// `npx endpointsweep` points you at the real tool instead of failing, and so
// the name cannot be claimed by someone else.
process.stdout.write(`
EndpointSweep is a Python tool, not an npm package.

  pipx install endpointsweep     (recommended)
  pip install endpointsweep

Then:

  endpointsweep scan             audit this machine
  esweep --help                  short alias

Docs and source:
  https://github.com/harish-ravichandra/endpointsweep
`);
