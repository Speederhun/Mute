# Security policy

## Reporting a vulnerability

Please report security problems **privately** through GitHub
(Security tab > "Report a vulnerability") and do not open a public issue.
Include the version (`mute --help` prints the options, the release tag is the version), your OS, and steps to reproduce.

## Scope and honesty

Mute is a small, **unaudited** project. It uses the Noise protocol through a library, but the code around it
(framing, file transfer, relay mode, scrubbing, UI) has not had an independent review. Do not rely on it where a
failure could put someone in danger without getting a review first.

What is tested automatically (CI, every push, Windows + Linux + macOS):
tampered, replayed and reordered frames are rejected; garbage never completes a handshake; a wrong or missing
shared secret is rejected; closed mode rejects unknown peers; resumable transfers match their hash; metadata
scrubbers survive random input. What is **not** covered: real Tor networks, real-world traffic analysis,
operating-system level leaks (swap, crash dumps, thumbnails), and side channels.

## Dependencies

Installs from `requirements.lock` are hash-checked (`pip install --require-hashes -r requirements.lock`).
CI runs `pip-audit` and `bandit`; Dependabot proposes updates weekly.
