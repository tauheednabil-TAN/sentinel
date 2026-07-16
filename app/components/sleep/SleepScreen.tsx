"use client";

import { useMemo, useState } from "react";
import {
  bedtimesFor,
  wakeTimesFrom,
  formatClock,
  formatDuration,
} from "../../lib/storage";
import Icon from "./Icon";

const TIMER_CHOICES = [
  { label: "15m", minutes: 15 },
  { label: "30m", minutes: 30 },
  { label: "45m", minutes: 45 },
  { label: "1h", minutes: 60 },
  { label: "2h", minutes: 120 },
  { label: "4h", minutes: 240 },
  { label: "8h", minutes: 480 },
];

export default function SleepScreen({
  timerRemaining,
  onStartTimer,
  onCancelTimer,
  hasSound,
}: {
  timerRemaining: number | null;
  onStartTimer: (minutes: number) => void;
  onCancelTimer: () => void;
  hasSound: boolean;
}) {
  const [mode, setMode] = useState<"wake" | "now">("wake");
  const [wakeTime, setWakeTime] = useState("07:00");
  const [computedAt, setComputedAt] = useState(() => new Date());

  const cycleTimes = useMemo(() => {
    if (mode === "now") return wakeTimesFrom(computedAt);
    const [h, m] = wakeTime.split(":").map(Number);
    const wake = new Date(computedAt);
    wake.setHours(h, m, 0, 0);
    if (wake <= computedAt) wake.setDate(wake.getDate() + 1);
    return bedtimesFor(wake);
  }, [mode, wakeTime, computedAt]);

  return (
    <div className="fade-enter">
      <header className="mb-5 pt-2">
        <h1 className="text-[32px] font-bold tracking-tight">Sleep</h1>
        <p className="text-[15px]" style={{ color: "var(--ink-2)" }}>
          Timer & sleep-cycle planner
        </p>
      </header>

      {/* sleep timer */}
      <section className="glass rise-enter p-5">
        <div className="mb-3 flex items-center gap-2">
          <span style={{ color: "var(--accent)" }}>
            <Icon name="timer" size={20} />
          </span>
          <h2 className="text-[17px] font-bold">Sleep timer</h2>
        </div>

        {timerRemaining !== null ? (
          <div className="flex flex-col items-center py-3">
            <TimerRing remaining={timerRemaining} />
            <p className="mt-3 text-[13px]" style={{ color: "var(--ink-2)" }}>
              Sound fades out during the last 30 seconds
            </p>
            <button
              onClick={onCancelTimer}
              className="glass pressable mt-4 px-6 py-3 text-[15px] font-semibold"
              style={{ borderRadius: 999, color: "#ff7a8a" }}
            >
              Cancel timer
            </button>
          </div>
        ) : (
          <>
            <p className="mb-3 text-[13px]" style={{ color: "var(--ink-2)" }}>
              {hasSound
                ? "Sounds will fade out gently, then stop."
                : "Start some sounds first — the timer fades them out as you fall asleep."}
            </p>
            <div className="flex flex-wrap gap-2">
              {TIMER_CHOICES.map((c) => (
                <button
                  key={c.minutes}
                  onClick={() => onStartTimer(c.minutes)}
                  className="glass pressable px-4 py-2.5 text-[14px] font-semibold"
                  style={{ borderRadius: 999, color: "var(--accent)" }}
                >
                  {c.label}
                </button>
              ))}
            </div>
          </>
        )}
      </section>

      {/* sleep-cycle planner */}
      <section className="glass rise-enter mt-4 p-5" style={{ animationDelay: "80ms" }}>
        <div className="mb-3 flex items-center gap-2">
          <span style={{ color: "var(--accent)" }}>
            <Icon name="sunrise" size={20} />
          </span>
          <h2 className="text-[17px] font-bold">Sleep cycles</h2>
        </div>
        <p className="mb-4 text-[13px] leading-relaxed" style={{ color: "var(--ink-2)" }}>
          A full sleep cycle lasts about 90 minutes, and it takes ~15 minutes to fall
          asleep. Waking between cycles feels far better than waking mid-cycle.
        </p>

        <div className="glass mb-4 flex p-1" style={{ borderRadius: 999 }}>
          {(
            [
              { id: "wake", label: "Wake up at…" },
              { id: "now", label: "Sleep now" },
            ] as const
          ).map((m) => (
            <button
              key={m.id}
              onClick={() => {
                setMode(m.id);
                setComputedAt(new Date());
              }}
              className="pressable flex-1 rounded-full py-2 text-[13px] font-semibold"
              style={{
                background: mode === m.id ? "var(--accent-soft)" : "transparent",
                color: mode === m.id ? "var(--accent)" : "var(--ink-2)",
                transition: "background 0.3s ease",
              }}
            >
              {m.label}
            </button>
          ))}
        </div>

        {mode === "wake" && (
          <label className="mb-4 flex items-center justify-between gap-3">
            <span className="text-[14px] font-semibold" style={{ color: "var(--ink-2)" }}>
              I want to wake up at
            </span>
            <input
              type="time"
              value={wakeTime}
              onChange={(e) => {
                setWakeTime(e.target.value);
                setComputedAt(new Date());
              }}
              className="glass px-3 py-2 text-[16px] font-bold"
              style={{ borderRadius: 14, color: "var(--ink)", colorScheme: "inherit" }}
            />
          </label>
        )}

        <div className="grid grid-cols-2 gap-2.5">
          {cycleTimes.map(({ time, cycles }) => {
            const best = cycles === 5;
            return (
              <div
                key={cycles}
                className="glass flex flex-col items-center p-3"
                style={{
                  borderRadius: 20,
                  boxShadow: best
                    ? "0 0 0 1.5px var(--accent) inset, var(--glass-shadow)"
                    : undefined,
                }}
              >
                <span className="text-[20px] font-bold" style={{ color: best ? "var(--accent)" : "var(--ink)" }}>
                  {formatClock(time)}
                </span>
                <span className="text-[11px] font-semibold" style={{ color: "var(--ink-3)" }}>
                  {cycles} cycles · {(cycles * 1.5).toFixed(1).replace(".0", "")}h
                  {best ? " · ideal" : ""}
                </span>
              </div>
            );
          })}
        </div>
        <p className="mt-3 text-[12px]" style={{ color: "var(--ink-3)" }}>
          {mode === "wake"
            ? "Fall asleep at one of these times to wake refreshed."
            : "Set your alarm for one of these times."}
        </p>
      </section>
    </div>
  );
}

function TimerRing({ remaining }: { remaining: number }) {
  const r = 62;
  const c = 2 * Math.PI * r;
  // ring shows progress within the current hour (or the full remaining time if shorter)
  const cap = Math.max(remaining, 1);
  const window_ = Math.min(cap, 3600);
  const frac = (remaining % 3600) / window_ || 1;

  return (
    <div className="relative flex items-center justify-center">
      <svg width="160" height="160" viewBox="0 0 160 160">
        <circle cx="80" cy="80" r={r} fill="none" stroke="var(--accent-soft)" strokeWidth="9" />
        <circle
          cx="80"
          cy="80"
          r={r}
          fill="none"
          stroke="var(--accent)"
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - frac)}
          transform="rotate(-90 80 80)"
          style={{ transition: "stroke-dashoffset 1s linear" }}
        />
      </svg>
      <div className="absolute text-center">
        <div className="text-[30px] font-bold tabular-nums tracking-tight">
          {formatDuration(remaining)}
        </div>
        <div className="text-[12px] font-semibold" style={{ color: "var(--ink-3)" }}>
          remaining
        </div>
      </div>
    </div>
  );
}
