"use client";

import { PRESETS, SOUND_BY_ID } from "../../lib/catalog";
import { SavedMix } from "../../lib/storage";
import Icon from "./Icon";

export default function MixesScreen({
  savedMixes,
  currentMix,
  onApply,
  onSave,
  onDelete,
}: {
  savedMixes: SavedMix[];
  currentMix: Record<string, number>;
  onApply: (sounds: Record<string, number>) => void;
  onSave: (name: string) => void;
  onDelete: (id: string) => void;
}) {
  const hasCurrent = Object.keys(currentMix).length > 0;

  const saveCurrent = () => {
    const names = Object.keys(currentMix).map((id) => SOUND_BY_ID[id]?.name ?? id);
    onSave(names.slice(0, 2).join(" + ") + (names.length > 2 ? ` +${names.length - 2}` : ""));
  };

  return (
    <div className="fade-enter">
      <header className="mb-5 pt-2">
        <h1 className="text-[32px] font-bold tracking-tight">Mixes</h1>
        <p className="text-[15px]" style={{ color: "var(--ink-2)" }}>
          Curated blends & your creations
        </p>
      </header>

      {/* curated presets */}
      <div className="grid grid-cols-2 gap-3">
        {PRESETS.map((p, i) => (
          <button
            key={p.id}
            onClick={() => onApply(p.sounds)}
            className="glass pressable rise-enter relative flex flex-col items-start gap-1 overflow-hidden p-4 text-left"
            style={{ animationDelay: `${Math.min(i * 50, 400)}ms`, borderRadius: 26, minHeight: 156 }}
          >
            <span
              aria-hidden
              className="absolute inset-0 opacity-60"
              style={{
                background: `linear-gradient(135deg, hsla(${p.hues[0]}, 80%, 60%, 0.35), hsla(${p.hues[1]}, 80%, 55%, 0.18))`,
              }}
            />
            <span className="relative flex items-center gap-1.5">
              {Object.keys(p.sounds).slice(0, 3).map((id) => (
                <span
                  key={id}
                  className="flex h-8 w-8 items-center justify-center rounded-full"
                  style={{
                    background: "rgba(255,255,255,0.14)",
                    color: `hsl(${SOUND_BY_ID[id]?.hue ?? 220}, 85%, 76%)`,
                  }}
                >
                  <Icon name={SOUND_BY_ID[id]?.icon ?? "noise"} size={16} />
                </span>
              ))}
            </span>
            <span className="relative mt-auto text-[16px] font-bold">{p.name}</span>
            <span className="relative text-[12px] leading-snug" style={{ color: "var(--ink-2)" }}>
              {p.tagline}
            </span>
          </button>
        ))}
      </div>

      {/* saved mixes */}
      <div className="mt-7 mb-3 flex items-center justify-between">
        <h2 className="text-[20px] font-bold">My mixes</h2>
        {hasCurrent && (
          <button
            onClick={saveCurrent}
            className="glass pressable flex items-center gap-1.5 px-3.5 py-2 text-[13px] font-semibold"
            style={{ borderRadius: 999, color: "var(--accent)" }}
          >
            <Icon name="plus" size={15} strokeWidth={2.2} />
            Save current
          </button>
        )}
      </div>

      {savedMixes.length === 0 ? (
        <div className="glass p-5 text-center text-[14px]" style={{ color: "var(--ink-2)" }}>
          Nothing saved yet. Start some sounds, open the mixer and tap “Save mix”.
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {savedMixes.map((m) => (
            <div key={m.id} className="glass flex items-center gap-3 p-3.5" style={{ borderRadius: 24 }}>
              <button onClick={() => onApply(m.sounds)} className="pressable flex min-w-0 flex-1 items-center gap-3 text-left">
                <span
                  className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full"
                  style={{ background: "var(--accent-soft)", color: "var(--accent)" }}
                >
                  <Icon name="play" size={20} />
                </span>
                <span className="min-w-0">
                  <span className="block truncate text-[15px] font-semibold">{m.name}</span>
                  <span className="block truncate text-[12px]" style={{ color: "var(--ink-2)" }}>
                    {Object.keys(m.sounds)
                      .map((id) => SOUND_BY_ID[id]?.name ?? id)
                      .join(" · ")}
                  </span>
                </span>
              </button>
              <button
                onClick={() => onDelete(m.id)}
                className="pressable flex h-9 w-9 shrink-0 items-center justify-center rounded-full"
                style={{ color: "var(--ink-3)" }}
                aria-label={`Delete ${m.name}`}
              >
                <Icon name="trash" size={17} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
