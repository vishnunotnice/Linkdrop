/** Mirrored from crates/linkdrop-core. Keep this contract in sync with Rust serde names. */
export type TransferStatus = "pending" | "awaiting_approval" | "connecting" | "transferring" | "paused" | "completed" | "failed" | "cancelled";
export interface Device { id: string; display_name: string; operating_system: string; discovery_status: "offline" | "discoverable" | "found"; trust_status: "unknown" | "trusted" | "blocked"; last_seen: string | null; }
export interface Transfer { id: string; sender_device_id: string; receiver_device_id: string; filename: string; total_bytes: number; transferred_bytes: number; status: TransferStatus; created_at: string; }
export interface Settings { displayName: string; discoverable: boolean; downloadDirectory: string | null; }
