# Upstream route drift report

`scripts/route_drift.py` is a developer script. It compares the route registry in a
locally saved copy of upstream technocore-chat `src/app.py` with this guard's
classifier and writes a deterministic JSON report. It makes no network call, starts
no subprocess, and never imports or executes the upstream file: it reads it with `ast`.

## Producing the input

Fetching is a separate, human step. From an existing local clone of technocore-chat:

```text
git -C <technocore-chat clone> show <40-hex commit>:src/app.py > <scratch>/app-<commit>.py
```

Keep the copy outside this repository, for example in a scratch directory.

## Running it

```text
python scripts/route_drift.py --app-py <scratch>/app-<commit>.py --upstream-commit <40-hex commit> [--out report.json] [--fixture-out fixture.json] [--guard-src <dir>]
```

- `--upstream-commit` is recorded as given and must match `^[0-9a-f]{40}$`. The script
  cannot check that the file really came from that commit.
- Without `--out` the report goes to stdout.
- `--fixture-out` also writes `{"source", "commit", "routes": [[path, [methods]], ...]}`.
  This follows PR #1's `upstream-routes-*.json` layout but has no `version` key, and its
  rows are sorted by path rather than in registration order. Only the paths you pass are written.
- `--guard-src` classifies with another checkout's `src` directory instead of this one.
- Exit codes: `0` no drift, `1` drift, `2` usage, read, write, extraction or sample error.

The parser understands exactly five element shapes inside the module-level
`app = Starlette(routes=[...])`: `Route("<path>", name)`, `Route("<path>", name, methods=[...])`,
`_get_write("<path>", name)`, and `*[Route(path, name) for path in (<literal tuple>)]` or
`... for path in _DOCS` with literal dict keys. Anything else (a new shape, a non-literal path)
exits `2` naming the line. Treat that as a signal to review upstream by hand, not as something
to work around. Registration outside the list is detected by name only: `app.<method>` such as
`app.add_route`, and rebinding or mutating `app` or `_DOCS`. Aliases and `getattr` are not
followed, and `Route` and `_get_write` are trusted by name.

## What the report lists

Each route and method is classified by `inspect_url` against a sample URL built from fixed
placeholder values. Only path templates appear in the report, never sample URLs or values.
A sample the guard returns as `blocked` exits `2` (`sample_rejected`). A sample its validators
refuse comes back as effect `unknown` and is listed as `uncovered`, the safe direction.

- `upstream_routes`: every registered path with its merged methods. HEAD is added wherever
  Starlette adds it; `_get_write` routes are GET only.
- `classified`: the guard's `effect` and `route_id` for each path and method.
- `uncovered`: entries whose effect is `unknown`. The guard refuses them; the policy has not
  reviewed them.
- `write_misclassified`: `_get_write` routes and POST methods whose effect is not `write`.
  These are the dangerous cases: upstream mutates state but the guard does not call it a write.
  It knows only those two signals. A plain `Route` whose handler writes is invisible to it.
- `stale_static_paths`: `STATIC_READ_PATHS` entries that upstream no longer registers.
- `drift`: true when any of the three lists above is non-empty.

## What a clean report does not prove

- It does not show that the deployed service matches the saved `app.py`, or that the saved file
  came from the commit you named.
- It checks one sample per template. It does not check query keys (a known limitation: no query
  parameter drift analysis), request bodies, headers, or handler semantics such as a GET that
  writes only under some query values.
- It does not show that a covered route is classified correctly for every input, only for the
  sample.

## Acting on drift

The report is evidence for a human, not a policy update. Changing route classification still
follows AGENTS.md section 4: a policy entry, positive, wrong-method, redaction and adversarial
encoding tests, and a human-reviewed official baseline update. Do not edit the policy or the
classifier from the report alone.
