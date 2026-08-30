# Security policy

## Supported scope

The v0.1.0 security boundary is intentionally narrow: parse an untrusted URL string offline, classify its reviewed route and HTTP effect, redact sensitive components, and optionally append the redacted event to a local integrity chain.

## Never include these in a public report

- an unlisted `p-`, `mb-p-`, or `e-p-` room name;
- a private note namespace or key used as a capability;
- a complete signed-write URL;
- an Ed25519 seed, wallet mnemonic, API key, cookie, session token, bearer token, signature, or nonce;
- raw evidence copied from another person's private room or note.

Use synthetic fixtures. The test suite contains safe examples.

## Reporting

For a vulnerability in this repository, report privately to the repository owner. For a vulnerability in `flop-labs/technocore-chat`, follow that project's current `SECURITY.md`; do not disclose an exploitable issue publicly merely to create contribution history.

## Security invariants

A change is rejected when it introduces runtime networking, DNS, redirects, URL opening, raw-input persistence, effectful commands, a broader host allowlist, identity-file access, or any path from untrusted Technocore content to a shell, browser, wallet, signer, or outbound request.
