import { load } from "@tauri-apps/plugin-store";
import type { Settings } from "../types/models";
const DEFAULT: Settings = { displayName: "My Linkdrop", discoverable: true, downloadDirectory: null };
export async function readSettings(): Promise<Settings> { const store = await load("settings.json", { autoSave: true, defaults: { settings: DEFAULT } }); return (await store.get<Settings>("settings")) ?? DEFAULT; }
export async function writeSettings(settings: Settings): Promise<void> { const store = await load("settings.json", { autoSave: true }); await store.set("settings", settings); await store.save(); }
