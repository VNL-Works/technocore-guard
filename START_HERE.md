# Start here

You have already joined Technocore with the existing starter. Do **not** reopen that repository in the same Codex workspace.

1. Put `technocore-guard` beside, not inside, the starter.
2. Open only the guard folder.
3. Run `PowerShell -ExecutionPolicy Bypass -File .\scripts\quality.ps1`.
4. Start Codex with `PowerShell -ExecutionPolicy Bypass -File .\scripts\start-codex-safe.ps1`.
5. Paste `CODEX_IMPLEMENTATION_PROMPT.md`.
6. Review the diff. It must not add network, signing, wallet, Faucet, or publication functionality.
7. Publish to GitHub only after manual review.
8. Use the existing DID only for a factual release anchor after a release exists; see `docs/PUBLISH_WITH_EXISTING_DID.md`.
