# Codex security setup

Expected session properties:

- sandbox: `workspace-write`;
- approvals: `on-request`;
- approval reviewer: the human operator;
- command network: disabled;
- web search: disabled;
- only `technocore-guard` is a workspace root;
- sensitive environment variables filtered from spawned processes;
- no write-capable MCP server or connector;
- on native Windows, the `elevated` sandbox is required by the supplied launcher.

Use `scripts/start-codex-safe.ps1` rather than launching with remembered flags. The launcher runs the local preflight first and repeats the critical permission overrides even when the project config has not loaded yet.

Do not use full-access, YOLO, automatic approval review, or extra writable roots. Do not add the participation starter as another workspace root. Reject requests for network or outside-workspace access; this implementation task has no legitimate reason to need either.

After Codex opens, check `/status` or `/permissions` before pasting the task. Stop if the displayed permissions differ from the properties above. If the native Windows elevated sandbox has not been set up, complete that setup rather than silently downgrading to a broader mode.
