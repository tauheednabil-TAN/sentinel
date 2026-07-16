"use client";

import { useState } from "react";
import { CATEGORIES, SOUNDS, Category } from "../../lib/catalog";
import Icon from "./Icon";

export default function SoundsScreen({
  mix,
  onToggle,
}: {
  mix: Record<string, number>;
  onToggle: (id: string) => void;
}) {
  const [category, setCategory] = useState<Category | "all">("all");
  const visible = SOUNDS.filter((s) => category === "all" || s.category === category);

  return (
    <div className="fade-enter">
      <header className="mb-5 pt-2">
        <h1 className="text-[32px] font-bold tracking-tight">Nocturne</h1>
        <p className="text-[15px]" style={{ color: "var(--ink-2)" }}>
          Mix sounds to drift away
        </p>
      </header>

      {/* category chips */}
      <div className="no-scrollbar -mx-5 mb-5 flex gap-2 overflow-x-auto px-5 pb-1">
        {CATEGORIES.map((c) => {
          const active = category === c.id;
          return (
            <button
              key={c.id}
              onClick={() => setCategory(c.id)}
              className="glass pressable shrink-0 px-4 py-2 text-[13px] font-semibold"
              style={{
                borderRadius: 999,
                color: active ? "var(--accent)" : "var(--ink-2)",
                boxShadow: active
                  ? "0 0 0 1.5px var(--accent) inset, var(--glass-shadow)"
                  : undefined,
              }}
            >
              {c.label}
            </button>
          );
        })}
      </div>

      {/* sound grid */}
      <div className="grid grid-cols-3 gap-3">
        {visible.map((s, i) => {
          const active = mix[s.id] !== undefined;
          return (
            <button
              key={s.id}
              onClick={() => onToggle(s.id)}
              className="glass pressable rise-enter relative flex aspect-square flex-col items-center justify-center gap-2 p-2"
              style={{
                animationDelay: `${Math.min(i * 40, 400)}ms`,
                borderRadius: 26,
                boxShadow: active
                  ? `0 0 0 1.5px hsl(${s.hue}, 85%, 70%) inset, 0 0 28px hsla(${s.hue}, 90%, 65%, 0.35), var(--glass-shadow)`
                  : undefined,
              }}
              aria-pressed={active}
            >
              <span
                className="flex h-12 w-12 items-center justify-center rounded-full"
                style={{
                  background: `hsla(${s.hue}, 80%, 70%, ${active ? 0.3 : 0.14})`,
                  color: `hsl(${s.hue}, 85%, ${active ? 78 : 68}%)`,
                  transition: "background 0.3s ease",
                }}
              >
                <Icon name={s.icon} />
              </span>
              <span
                className="px-1 text-center text-[12px] font-semibold leading-tight"
                style={{ color: active ? "var(--ink)" : "var(--ink-2)" }}
              >
                {s.name}
              </span>
              {s.headphones && (
                <span
                  className="absolute right-2.5 top-2.5"
                  style={{ color: "var(--ink-3)" }}
                  title="Headphones recommended"
                >
                  <Icon name="headphones" size={13} strokeWidth={2} />
                </span>
              )}
              {active && (
                <span
                  className="pulse-dot absolute left-3 top-3 h-2 w-2 rounded-full"
                  style={{ background: `hsl(${s.hue}, 90%, 70%)` }}
                />
              )}
            </button>
          );
        })}
      </div>

      <p className="mt-5 text-center text-[12px]" style={{ color: "var(--ink-3)" }}>
        Every sound is generated live on your device — endless, never looping.
      </p>
    </div>
  );
}
