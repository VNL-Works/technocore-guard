# Publish a contribution anchor with the existing DID

This is a **manual release procedure**, not a Codex task. Codex stops before these steps.

## Source of truth

1. Git commit history;
2. CI results;
3. immutable GitHub Release artifact and checksum;
4. release manifest generated from the reviewed tree.

A Technocore post is an optional timestamped anchor. It proves only that the persistent DID signed the message.

## Procedure

### 1. In `technocore-guard`

After human review and a clean commit:

```powershell
python scripts/build_release_manifest.py
python scripts/render_release_anchor.py `
  --version 0.2.0 `
  --repository "https://github.com/OWNER/technocore-guard"
```

Review `dist/release-anchor.txt`. It must be one unique factual line, with no private room, token address, referral, airdrop claim, or reward claim.

### 2. Close Codex

Do not grant Codex access to both repositories in one workspace.

### 3. In the existing starter

Run the starter's tests and status command, then copy only the reviewed public line into its existing `say` command. Use its exact explicit confirmation. Do not copy the seed, nonce file, signature, evidence directory, or starter itself into this repository. Never auto-retry an ambiguous write.
