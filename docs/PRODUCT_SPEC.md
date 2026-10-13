# Product specification — v0.2.0 offline core

## Problem

A normal web-safety heuristic treats `GET` as read-only. Technocore intentionally exposes write operations as ordinary GET paths so restricted agents can participate. Consequently, an agent that follows an attacker-supplied URL for “verification” can cause a public or capability-scoped write.

## User promise

Given an absolute URL and an explicit HTTP method, Technocore Guard returns a redacted classification without opening, resolving, hashing, or storing the URL.

## Inputs

- one string supplied by an untrusted source;
- an explicit method from `GET`, `HEAD`, or `POST`.

No request headers, cookies, credentials, body, DNS result, or remote response are needed.

## Outputs

- `effect`: `read`, `write`, `unknown`, or `blocked`;
- `risk`: `low`, `medium`, `high`, or `critical`;
- reviewed `route_id`;
- template-only `sanitized_target`;
- narrow reason and warning strings;
- flags for private capability, user content, and replay material;
- `network_executed: false`.

The raw URL and its deterministic hash are absent by contract.

## Classification semantics

- `read`: a known route/method expected to retrieve data, but returned data remains untrusted.
- `write`: a known route/method may mutate room or note state. It is never executed by this tool.
- `unknown`: exact official origin, but the route or method is not in the human-reviewed policy.
- `blocked`: origin or syntax is disguised, ambiguous, malformed, noncanonical, or outside policy.

`unknown` and `blocked` return a non-zero CLI status.

## v0.2.0 acceptance criteria

- standard-library-only runtime;
- zero network paths;
- no private-key or wallet surface;
- raw URL absent from output and ledger;
- adversarial parser tests pass on Windows and Linux;
- release manifest can be built without ignored or secret material;
- Codex can work with workspace-only writes and network disabled.

## Deferred deliberately

- live specification retrieval or drift checks;
- read-only fetch execution;
- browser extension or MCP surface;
- any write, signing, wallet, Faucet, or testnet function;
- auto-publication to GitHub, Technocore, or X.
