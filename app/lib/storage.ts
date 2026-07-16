// localStorage persistence for saved mixes and preferences.

export interface SavedMix {
  id: string;
  name: string;
  sounds: Record<string, number>;
  createdAt: number;
}

const MIXES_KEY = "nocturne.mixes";
const LAST_MIX_KEY = "nocturne.lastMix";
const MASTER_KEY = "nocturne.masterVolume";

function read<T>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback;
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function write(key: string, value: unknown) {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // storage may be unavailable (private mode); the app still works
  }
}

export const loadMixes = (): SavedMix[] => read<SavedMix[]>(MIXES_KEY, []);
export const saveMixes = (mixes: SavedMix[]) => write(MIXES_KEY, mixes);

export const loadLastMix = (): Record<string, number> =>
  read<Record<string, number>>(LAST_MIX_KEY, {});
export const saveLastMix = (mix: Record<string, number>) => write(LAST_MIX_KEY, mix);

export const loadMasterVolume = (): number => read<number>(MASTER_KEY, 0.9);
export const saveMasterVolume = (v: number) => write(MASTER_KEY, v);

// ---- sleep-cycle math -------------------------------------------------------
// A full sleep cycle averages 90 minutes and falling asleep ~15 minutes.

export const CYCLE_MIN = 90;
export const FALL_ASLEEP_MIN = 15;

/** Best times to fall asleep if you must wake at `wake` (4–6 full cycles). */
export function bedtimesFor(wake: Date): { time: Date; cycles: number }[] {
  return [6, 5, 4, 3].map((cycles) => ({
    cycles,
    time: new Date(wake.getTime() - (cycles * CYCLE_MIN + FALL_ASLEEP_MIN) * 60_000),
  }));
}

/** Best times to wake if you go to sleep now. */
export function wakeTimesFrom(now: Date): { time: Date; cycles: number }[] {
  return [3, 4, 5, 6].map((cycles) => ({
    cycles,
    time: new Date(now.getTime() + (cycles * CYCLE_MIN + FALL_ASLEEP_MIN) * 60_000),
  }));
}

export function formatClock(d: Date): string {
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function formatDuration(totalSeconds: number): string {
  const s = Math.max(0, Math.round(totalSeconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
  return `${m}:${String(sec).padStart(2, "0")}`;
}
