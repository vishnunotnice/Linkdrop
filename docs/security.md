# Security assumptions

At first launch, Linkdrop creates an Ed25519 signing key using the operating system cryptographic random number generator. The desktop adapter stores the raw key in the platform credential store (Keychain on macOS, Credential Manager on Windows, Secret Service where available). Only a BLAKE3 digest of the public key is used as the stable device ID. Private key bytes are neither logged nor sent to the frontend.

If the credential store is unavailable, Linkdrop logs a warning and creates an ephemeral identity for that run; it does not write private material to an unprotected application file. This behavior is a conservative fallback but means identity does not persist.

Phase 1 does not perform discovery, pairing, TLS, or transfers. Future pairing must present and verify public key fingerprints before creating a trusted-device record. QUIC connections will use TLS 1.3 authenticated with the persistent device identity. Linkdrop is not audited and must not be represented as production-secure.

Phase 2 mDNS advertisements contain only a public device ID, display name, OS, protocol version, and discovery capability. Every advertisement is untrusted input, strictly size-validated, and can be spoofed. Discovery never implies trust or pairing and never publishes private key material.
