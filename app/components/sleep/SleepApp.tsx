"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getEngine } from "../../lib/audio-engine";
import { SOUND_BY_ID } from "../../lib/catalog";
import {
  SavedMix,
  loadMasterVolume,
  loadMixes,
  saveLastMix,
  saveMasterVolume,
  saveMixes,
  formatDuration,
} from "../../lib/storage";
import Icon from "./Icon";
import SoundsScreen from "./SoundsScreen";
import MixesScreen from "./MixesScreen";
import SleepScreen from "./SleepScreen";
import BreatheScreen from "./BreatheScreen";

export type Tab = "sounds" | "mixes" | "sleep" | "breathe";

const FADE_SECONDS = 30;

const TABS: { id: Tab; label: string; icon: string }[] = [
  { id: "sounds", label: "Sounds", icon: "moon" },
  { id: "mixes", label: "Mixes", icon: "mixes" },
  { id: "sleep", label: "Sleep", icon: "timer" },
  { id: "breathe", label: "Breathe", icon: "breathe" },
];

export default function SleepApp() {
  const [tab, setTab] = useState<Tab>("sounds");
  const [mix, setMix] = useState<Record<string, number>>({});
  const [paused, setPaused] = useState(false);
  const [mixerOpen, setMixerOpen] = useState(false);
  const [masterVolume, setMasterVolumeState] = useState(0.9);
  const [savedMixes, setSavedMixes] = useState<SavedMix[]>([]);
  const [timerEnd, setTimerEnd] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const fadeStarted = useRef(false);

  const engine = useMemo(() => (typeof window !== "undefined" ? getEngine() : null), []);

  useEffect(() => {
    // deferred so hydration completes before localStorage state lands
    const t = window.setTimeout(() => {
      setSavedMixes(loadMixes());
      const v = loadMasterVolume();
      setMasterVolumeState(v);
      engine?.setMasterVolume(v);
    }, 0);
    return () => window.clearTimeout(t);
  }, [engine]);

  useEffect(() => {
    saveLastMix(mix);
  }, [mix]);

  // ---- sound control -------------------------------------------------------

  const toggleSound = useCallback(
    (id: string) => {
      if (!engine) return;
      setMix((prev) => {
        const next = { ...prev };
        if (next[id] !== undefined) {
          engine.stop(id);
          delete next[id];
        } else {
          const vol = SOUND_BY_ID[id]?.defaultVolume ?? 0.6;
          void engine.start(id, vol);
          next[id] = vol;
        }
        return next;
      });
      setPaused(false);
    },
    [engine]
  );

  const setSoundVolume = useCallback(
    (id: string, volume: number) => {
      engine?.setVolume(id, volume);
      setMix((prev) => ({ ...prev, [id]: volume }));
    },
    [engine]
  );

  const applyMix = useCallback(
    (sounds: Record<string, number>) => {
      if (!engine) return;
      engine.stopAll();
      Object.entries(sounds).forEach(([id, vol]) => void engine.start(id, vol));
      setMix({ ...sounds });
      setPaused(false);
      setTab("sounds");
    },
    [engine]
  );

  const stopAll = useCallback(() => {
    engine?.stopAll();
    engine?.restoreMaster();
    setMix({});
    setMixerOpen(false);
    setTimerEnd(null);
    fadeStarted.current = false;
  }, [engine]);

  const togglePause = useCallback(() => {
    if (!engine) return;
    if (paused) {
      void engine.resume();
      setPaused(false);
    } else {
      void engine.pause();
      setPaused(true);
    }
  }, [engine, paused]);

  const setMaster = useCallback(
    (v: number) => {
      setMasterVolumeState(v);
      engine?.setMasterVolume(v);
      saveMasterVolume(v);
    },
    [engine]
  );

  // ---- saved mixes ---------------------------------------------------------

  const saveCurrentMix = useCallback(
    (name: string) => {
      const entry: SavedMix = {
        id: `mix-${Date.now()}`,
        name,
        sounds: { ...mix },
        createdAt: Date.now(),
      };
      setSavedMixes((prev) => {
        const next = [entry, ...prev];
        saveMixes(next);
        return next;
      });
    },
    [mix]
  );

  const deleteMix = useCallback((id: string) => {
    setSavedMixes((prev) => {
      const next = prev.filter((m) => m.id !== id);
      saveMixes(next);
      return next;
    });
  }, []);

  // ---- sleep timer ---------------------------------------------------------

  const startTimer = useCallback((minutes: number) => {
    fadeStarted.current = false;
    setTimerEnd(Date.now() + minutes * 60_000);
  }, []);

  const cancelTimer = useCallback(() => {
    setTimerEnd(null);
    fadeStarted.current = false;
    engine?.restoreMaster();
  }, [engine]);

  useEffect(() => {
    if (timerEnd === null) return;
    const tick = window.setInterval(() => {
      const ts = Date.now();
      setNow(ts);
      const remaining = (timerEnd - ts) / 1000;
      if (!engine) return;
      if (remaining <= 0) {
        engine.stopAll();
        engine.restoreMaster();
        setMix({});
        setTimerEnd(null);
        fadeStarted.current = false;
      } else if (remaining <= FADE_SECONDS && !fadeStarted.current) {
        fadeStarted.current = true;
        engine.fadeOut(remaining);
      }
    }, 1000);
    return () => window.clearInterval(tick);
  }, [timerEnd, engine]);

  const timerRemaining = timerEnd !== null ? Math.max(0, (timerEnd - now) / 1000) : null;
  const activeCount = Object.keys(mix).length;
  const activeNames = Object.keys(mix)
    .map((id) => SOUND_BY_ID[id]?.name ?? id)
    .join(" · ");

  return (
    <div className="relative min-h-dvh">
      <div className="sky" aria-hidden>
        <div className="aurora aurora-1" />
        <div className="aurora aurora-2" />
        <div className="aurora aurora-3" />
      </div>

      <main
        className="mx-auto w-full max-w-lg px-5 safe-top"
        style={{ paddingBottom: activeCount > 0 ? 190 : 120 }}
      >
        {tab === "sounds" && <SoundsScreen mix={mix} onToggle={toggleSound} />}
        {tab === "mixes" && (
          <MixesScreen
            savedMixes={savedMixes}
            currentMix={mix}
            onApply={applyMix}
            onSave={saveCurrentMix}
            onDelete={deleteMix}
          />
        )}
        {tab === "sleep" && (
          <SleepScreen
            timerRemaining={timerRemaining}
            onStartTimer={startTimer}
            onCancelTimer={cancelTimer}
            hasSound={activeCount > 0}
          />
        )}
        {tab === "breathe" && <BreatheScreen />}
      </main>

      {/* Now-playing bar */}
      {activeCount > 0 && (
        <div className="fixed inset-x-0 z-30" style={{ bottom: "calc(max(env(safe-area-inset-bottom), 12px) + 78px)" }}>
          <div className="mx-auto w-full max-w-lg px-5">
            <div className="glass-strong rise-enter flex items-center gap-3 px-4 py-3" style={{ borderRadius: 24 }}>
              <button
                onClick={togglePause}
                className="pressable flex h-11 w-11 shrink-0 items-center justify-center rounded-full"
                style={{ background: "var(--accent-soft)", color: "var(--accent)" }}
                aria-label={paused ? "Play" : "Pause"}
              >
                <Icon name={paused ? "play" : "pause"} size={22} />
              </button>
              <button className="min-w-0 flex-1 text-left" onClick={() => setMixerOpen(true)}>
                <div className="truncate text-[15px] font-semibold">{activeNames}</div>
                <div className="text-[12px]" style={{ color: "var(--ink-2)" }}>
                  {activeCount} sound{activeCount > 1 ? "s" : ""}
                  {timerRemaining !== null && ` · ${formatDuration(timerRemaining)} left`}
                </div>
              </button>
              <button
                onClick={() => setMixerOpen(true)}
                className="pressable flex h-11 w-11 shrink-0 items-center justify-center rounded-full"
                style={{ background: "var(--accent-soft)", color: "var(--accent)" }}
                aria-label="Open mixer"
              >
                <Icon name="sliders" size={20} />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Floating glass tab bar */}
      <nav className="fixed inset-x-0 bottom-0 z-30 safe-bottom">
        <div className="mx-auto w-full max-w-lg px-5 pb-1">
          <div className="glass-strong flex items-center justify-around px-2 py-2" style={{ borderRadius: 999 }}>
            {TABS.map((t) => {
              const active = tab === t.id;
              return (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className="pressable flex flex-col items-center gap-0.5 rounded-full px-4 py-1.5"
                  style={{
                    color: active ? "var(--accent)" : "var(--ink-3)",
                    background: active ? "var(--accent-soft)" : "transparent",
                    transition: "background 0.3s ease, color 0.3s ease",
                  }}
                >
                  <Icon name={t.icon} size={24} strokeWidth={active ? 2.1 : 1.7} />
                  <span className="text-[10px] font-semibold tracking-wide">{t.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </nav>

      {/* Mixer bottom sheet */}
      {mixerOpen && (
        <MixerSheet
          mix={mix}
          masterVolume={masterVolume}
          onClose={() => setMixerOpen(false)}
          onVolume={setSoundVolume}
          onToggle={toggleSound}
          onMaster={setMaster}
          onStopAll={stopAll}
          onSave={saveCurrentMix}
        />
      )}
    </div>
  );
}

// ---- mixer sheet ------------------------------------------------------------

function MixerSheet({
  mix,
  masterVolume,
  onClose,
  onVolume,
  onToggle,
  onMaster,
  onStopAll,
  onSave,
}: {
  mix: Record<string, number>;
  masterVolume: number;
  onClose: () => void;
  onVolume: (id: string, v: number) => void;
  onToggle: (id: string) => void;
  onMaster: (v: number) => void;
  onStopAll: () => void;
  onSave: (name: string) => void;
}) {
  const [saved, setSaved] = useState(false);
  const ids = Object.keys(mix);

  const handleSave = () => {
    const names = ids.map((id) => SOUND_BY_ID[id]?.name ?? id);
    onSave(names.slice(0, 2).join(" + ") + (names.length > 2 ? ` +${names.length - 2}` : ""));
    setSaved(true);
    window.setTimeout(() => setSaved(false), 1600);
  };

  return (
    <div className="fixed inset-0 z-40 flex items-end justify-center">
      <button
        className="fade-enter absolute inset-0"
        style={{ background: "rgba(0,0,0,0.4)" }}
        onClick={onClose}
        aria-label="Close mixer"
      />
      <div
        className="glass-strong sheet-enter relative w-full max-w-lg px-5 pt-3 safe-bottom"
        style={{ borderRadius: "32px 32px 0 0", maxHeight: "78dvh", overflowY: "auto" }}
      >
        <div
          className="mx-auto mb-4 h-1.5 w-10 rounded-full"
          style={{ background: "var(--ink-3)" }}
        />
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-[20px] font-bold">Mixer</h2>
          <button
            onClick={onClose}
            className="pressable flex h-9 w-9 items-center justify-center rounded-full"
            style={{ background: "var(--accent-soft)", color: "var(--ink-2)" }}
            aria-label="Close"
          >
            <Icon name="close" size={18} />
          </button>
        </div>

        {ids.length === 0 ? (
          <p className="py-8 text-center text-[15px]" style={{ color: "var(--ink-2)" }}>
            No sounds playing. Pick some from the Sounds tab.
          </p>
        ) : (
          <div className="flex flex-col gap-4">
            {ids.map((id) => {
              const def = SOUND_BY_ID[id];
              const vol = mix[id];
              return (
                <div key={id} className="flex items-center gap-3">
                  <div
                    className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl"
                    style={{
                      background: `hsla(${def?.hue ?? 220}, 80%, 70%, 0.18)`,
                      color: `hsl(${def?.hue ?? 220}, 85%, 74%)`,
                    }}
                  >
                    <Icon name={def?.icon ?? "noise"} size={22} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="mb-0.5 truncate text-[14px] font-semibold">{def?.name ?? id}</div>
                    <input
                      type="range"
                      className="glass-slider"
                      min={0}
                      max={1}
                      step={0.01}
                      value={vol}
                      style={{ ["--fill" as string]: `${vol * 100}%` }}
                      onChange={(e) => onVolume(id, Number(e.target.value))}
                      aria-label={`${def?.name ?? id} volume`}
                    />
                  </div>
                  <button
                    onClick={() => onToggle(id)}
                    className="pressable flex h-9 w-9 shrink-0 items-center justify-center rounded-full"
                    style={{ color: "var(--ink-3)" }}
                    aria-label={`Remove ${def?.name ?? id}`}
                  >
                    <Icon name="close" size={16} />
                  </button>
                </div>
              );
            })}
          </div>
        )}

        <div className="mt-6 border-t pt-4" style={{ borderColor: "var(--glass-stroke)" }}>
          <div className="mb-1 flex items-center justify-between text-[13px] font-semibold" style={{ color: "var(--ink-2)" }}>
            <span>Master volume</span>
            <span>{Math.round(masterVolume * 100)}%</span>
          </div>
          <input
            type="range"
            className="glass-slider"
            min={0}
            max={1}
            step={0.01}
            value={masterVolume}
            style={{ ["--fill" as string]: `${masterVolume * 100}%` }}
            onChange={(e) => onMaster(Number(e.target.value))}
            aria-label="Master volume"
          />
        </div>

        {ids.length > 0 && (
          <div className="mt-4 mb-2 flex gap-3">
            <button
              onClick={handleSave}
              className="glass pressable flex-1 py-3.5 text-[15px] font-semibold"
              style={{ borderRadius: 20, color: "var(--accent)" }}
            >
              {saved ? "Saved ✓" : "Save mix"}
            </button>
            <button
              onClick={onStopAll}
              className="glass pressable flex-1 py-3.5 text-[15px] font-semibold"
              style={{ borderRadius: 20, color: "#ff7a8a" }}
            >
              Stop all
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
