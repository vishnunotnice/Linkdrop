# Planned protocol

Phase 2 will advertise only a versioned discovery record over local-network mDNS. A peer begins a QUIC connection and validates the peer identity against an explicit pairing decision; unknown peers are never trusted automatically. The transfer handshake exchanges metadata, requires receiver approval, and assigns an ID. Data is streamed in chunks authenticated by QUIC/TLS and checked with BLAKE3 before marking a transfer completed.

Discovery and transfer code are intentionally absent from Phase 1.

Phase 2 adds discovery-only mDNS using `_linkdrop._udp.local.`. Its advertised port is `0`, explicitly indicating that no transport endpoint exists. Pairing, authenticated QUIC, and file transfer remain future work.
