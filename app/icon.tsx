import { ImageResponse } from "next/og";

export const size = { width: 512, height: 512 };
export const contentType = "image/png";

// Crescent moon over a night-sky gradient — original artwork drawn in code.
export default function Icon() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "linear-gradient(160deg, #1b2150 0%, #0b1026 55%, #05070f 100%)",
          borderRadius: 96,
        }}
      >
        <svg width="330" height="330" viewBox="0 0 100 100">
          <circle cx="30" cy="22" r="2" fill="#cdd6ff" opacity="0.9" />
          <circle cx="76" cy="30" r="1.5" fill="#cdd6ff" opacity="0.7" />
          <circle cx="66" cy="14" r="1.2" fill="#cdd6ff" opacity="0.6" />
          <circle cx="20" cy="46" r="1.4" fill="#cdd6ff" opacity="0.55" />
          <path
            d="M 66 16 A 38 38 0 1 0 88 62 A 30 30 0 0 1 66 16 Z"
            fill="#aebafb"
          />
          <path
            d="M 66 16 A 38 38 0 1 0 88 62 A 30 30 0 0 1 66 16 Z"
            fill="url(#g)"
            opacity="0.5"
          />
          <defs>
            <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor="#ffffff" />
              <stop offset="100%" stopColor="#6f7fe8" />
            </linearGradient>
          </defs>
        </svg>
      </div>
    ),
    { ...size }
  );
}
