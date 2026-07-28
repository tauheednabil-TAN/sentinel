"use client";

import { useEffect, useRef, useState } from "react";

interface Pattern {
  id: string;
  name: string;
  description: string;
  /** [phase label, seconds, orb scale] */
  phases: [string, number, number][];
}

const PATTERNS: Pattern[] = [
  {
    id: "478",
    name: "4·7·8 Sleep",
    description: "The classic pre-sleep pattern: long exhales calm the nervous system.",
    phases: [
      ["Breathe in", 4, 1],
      ["Hold", 7, 1],
      ["Breathe out", 8, 0.55],
    ],
  },
  {
    id: "box",
    name: "Box Breathing",
    description: "Even 4-second sides. Steady, grounding, great for stress.",
    phases: [
      ["Breathe in", 4, 1],
      ["Hold", 4, 1],
      ["Breathe out", 4, 0.55],
      ["Hold", 4, 0.55],
    ],
  },
  {
    id: "coherent",
    name: "Coherent 5·5",
    description: "Five seconds in, five out — about six breaths a minute.",
    phases: [
      ["Breathe in", 5, 1],
      ["Breathe out", 5, 0.55],
    ],
  },
];

export default function BreatheScreen() {
  const [pattern, setPattern] = useState<Pattern>(PATTERNS[0]);
  const [running, setRunning] = useState(false);
  const [phaseIndex, setPhaseIndex] = useState(0);
  const [count, setCount] = useState(0);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    if (!running) return;
    const [, seconds] = pattern.phases[phaseIndex];
    const countdown = window.setInterval(() => {
      setCount((c) => Math.max(0, c - 1));
    }, 1000);
    timerRef.current = window.setTimeout(() => {
      const next = (phaseIndex + 1) % pattern.phases.length;
      setPhaseIndex(next);
      setCount(pattern.phases[next][1]);
    }, seconds * 1000) as unknown as number;
    return () => {
      window.clearInterval(countdown);
      if (timerRef.current) window.clearTimeout(timerRef.current);
    };
  }, [running, phaseIndex, pattern]);

  const start = () => {
    setPhaseIndex(0);
    setCount(pattern.phases[0][1]);
    setRunning(true);
  };

  const stop = () => {
    setRunning(false);
    setPhaseIndex(0);
  };

  const [label, seconds, scale] = pattern.phases[phaseIndex];

  return (
    <div className="fade-enter">
      <header className="mb-5 pt-2">
        <h1 className="text-[32px] font-bold tracking-tight">Breathe</h1>
        <p className="text-[15px]" style={{ color: "var(--ink-2)" }}>
          Guided breathing to unwind
        </p>
      </header>

      {/* orb */}
      <div className="relative mx-auto my-6 flex h-64 w-64 items-center justify-center">
        <div
          aria-hidden
          className="breathe-orb absolute h-56 w-56 rounded-full"
          style={{
            background:
              "radial-gradient(circle at 35% 30%, var(--accent-soft), transparent 70%)",
            boxShadow: "0 0 80px var(--accent-soft)",
            transform: `scale(${running ? scale : 0.75})`,
            transitionDuration: running ? `${seconds}s` : "1s",
          }}
        />
        <div
          className="glass-strong breathe-orb relative flex h-40 w-40 items-center justify-center rounded-full"
          style={{
            borderRadius: "50%",
            transform: `scale(${running ? scale : 0.85})`,
            transitionDuration: running ? `${seconds}s` : "1s",
          }}
        >
          <div className="text-center">
            <div className="text-[17px] font-bold">{running ? label : "Ready"}</div>
            {running && (
              <div className="text-[26px] font-bold tabular-nums" style={{ color: "var(--accent)" }}>
                {count}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="flex justify-center">
        <button
          onClick={running ? stop : start}
          className="glass-strong pressable px-10 py-3.5 text-[16px] font-bold"
          style={{ borderRadius: 999, color: running ? "#ff7a8a" : "var(--accent)" }}
        >
          {running ? "Stop" : "Begin"}
        </button>
      </div>

      {/* pattern picker */}
      <div className="mt-7 flex flex-col gap-3">
        {PATTERNS.map((p) => {
          const active = p.id === pattern.id;
          return (
            <button
              key={p.id}
              onClick={() => {
                setPattern(p);
                stop();
              }}
              className="glass pressable p-4 text-left"
              style={{
                borderRadius: 22,
                boxShadow: active
                  ? "0 0 0 1.5px var(--accent) inset, var(--glass-shadow)"
                  : undefined,
              }}
            >
              <div className="text-[15px] font-bold" style={{ color: active ? "var(--accent)" : "var(--ink)" }}>
                {p.name}
              </div>
              <div className="text-[13px] leading-snug" style={{ color: "var(--ink-2)" }}>
                {p.description}
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
