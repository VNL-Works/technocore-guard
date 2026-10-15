# Upstream and ecosystem notes

Baseline: `flop-labs/technocore-chat` version `0.14.5`, commit `0e47f770b13cc27e1e2e199d4cdf70a4778c97cc`, observed 2026-10-14 JST.

Previous baseline: version `0.10.0`, commit `7707cb63ebf638e8ef0cf59d1364818b9fef7d24`, observed 2026-08-30 JST.

The upstream project changes rapidly and receives many agent-assisted contributions. Before an upstream Issue or PR, a human must refresh official facts, search open and closed Issues/PRs, compare chronology and overlap, discuss substantial API changes first, include a failing reproduction for bugs, disclose AI assistance truthfully, use private disclosure for exploitable issues, and never attach unrelated URLs as evidence.

Related public discussions at the 2026-08-30 review (not refreshed on 2026-10-14):

- contribution-farming and fabricated evidence: issue 149;
- faux Faucet queue in world-writable notes: issue 368;
- independently verifiable receipts: issue 281;
- external authority/provenance adapters: issue 430;
- companion clients: issue 327;
- WebSub bridge: issue 329;
- overlapping-PR coordination and attribution: issue 479.

## 2026-10-14 baseline review: 7707cb6 to 0e47f77

The review read every commit in `7707cb6..0e47f77` that touches `src/`, from a local clone and
without network access. Conclusions:

- The route registry gained exactly one route, `/.well-known/mcp/server-card.json` (`GET`/`HEAD`).
  Its handler takes no query parameter and returns a generated JSON document. It is classified as
  a static-document read. Upstream does not register `/.well-known/mcp.json` or
  `/.well-known/mcp/server-cards.json`.
- For every existing policy route, the registered methods, the query keys the handler reads, and
  the read or write effect are unchanged. No `GET`/`HEAD` read handler gained a store write, and
  every write route is still a write.
- Upstream now counts a `ref=` query value of one fixed shape on any request, outside the
  handlers, and logs it when its debug logging is on. The guard does not allow `ref`, so a
  reviewed read carrying it is classified `unknown`, and a known write stays a write. The policy
  is unchanged.
- `scripts/route_drift.py` reports no drift against `0e47f77`.
- 2026-10-15: the HEAD model was checked against Starlette 1.7.0 and upstream 0e47f77's route
  objects, outside this repository. Starlette 1.7.0's `Route` adds HEAD to any GET route, and
  `Route.matches` compares the request method with the route's method set. The methods of the
  `Route` objects in upstream's `app` match the `upstream_routes` of `scripts/route_drift.py`
  for all 28 paths and 54 path/method pairs. Over raw ASGI, a HEAD to a `_get_write` route got
  405 with `Allow: GET` and the handler did not run, and a GET to the same route ran it.
