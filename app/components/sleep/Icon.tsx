// Hand-drawn SVG icon set, stroke-based to match the SF Symbols feel.

interface IconProps {
  name: string;
  size?: number;
  strokeWidth?: number;
}

export default function Icon({ name, size = 26, strokeWidth = 1.8 }: IconProps) {
  const common = {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
  };

  switch (name) {
    case "rain":
      return (
        <svg {...common}>
          <path d="M7 15a5 5 0 0 1-.6-9.97A6 6 0 0 1 18 6.3 4 4 0 0 1 17.5 15" />
          <path d="M8 18l-1 2.5M12.5 17.5l-1 2.5M17 18l-1 2.5" />
        </svg>
      );
    case "thunder":
      return (
        <svg {...common}>
          <path d="M7 13a5 5 0 0 1-.6-9.97A6 6 0 0 1 18 4.3 4 4 0 0 1 17.5 13" />
          <path d="M13 12l-3.5 5H12l-1.5 4.5L15 16h-2.5L14 12z" />
        </svg>
      );
    case "ocean":
      return (
        <svg {...common}>
          <path d="M2 12c2 0 2.5-1.6 4.5-1.6S9 12 11 12s2.5-1.6 4.5-1.6S18 12 20 12s2-.8 2-.8" />
          <path d="M2 17c2 0 2.5-1.6 4.5-1.6S9 17 11 17s2.5-1.6 4.5-1.6S18 17 20 17s2-.8 2-.8" />
          <path d="M13 7c1.6 0 2-1.3 3.6-1.3S18.4 7 20 7" />
        </svg>
      );
    case "stream":
      return (
        <svg {...common}>
          <path d="M4 5c3 0 3 2 6 2s3-2 6-2 3 2 4 2" />
          <path d="M4 12c3 0 3 2 6 2s3-2 6-2 3 2 4 2" />
          <path d="M4 19c3 0 3 2 6 2" opacity="0" />
          <path d="M6 19c2.5 0 2.5-2 5-2s2.5 2 5 2" />
        </svg>
      );
    case "wind":
      return (
        <svg {...common}>
          <path d="M3 8h11a2.5 2.5 0 1 0-2.5-2.5" />
          <path d="M3 13h15.5A2.5 2.5 0 1 1 16 15.5" />
          <path d="M3 18h8a2 2 0 1 1-2 2" />
        </svg>
      );
    case "bird":
      return (
        <svg {...common}>
          <path d="M16 7a3.5 3.5 0 0 0-7 .5v3C9 14 6 16 3 16.5c4 2.5 11 3 13.5-2.5" />
          <path d="M9 7.5C9 5 11 3 13.5 3c1.8 0 3.4 1 4.2 2.6L21 7l-3 1" />
          <path d="M10 21l3-4.5" />
          <circle cx="14.2" cy="6" r="0.4" fill="currentColor" />
        </svg>
      );
    case "cricket":
      return (
        <svg {...common}>
          <ellipse cx="12" cy="13" rx="6.5" ry="4.2" />
          <path d="M6.5 11L3 8M17.5 11L21 8" />
          <path d="M8 17l-1.5 3M16 17l1.5 3" />
          <path d="M7 13.5c3-1.8 7-1.8 10 0" />
        </svg>
      );
    case "fire":
      return (
        <svg {...common}>
          <path d="M12 21c-4 0-6.5-2.6-6.5-6 0-3 2-5 3.5-7 .4 1.4 1 2.2 2 3C11 8.5 11.5 5 14 3c0 3 4.5 5 4.5 10 0 4.4-2.5 8-6.5 8z" />
          <path d="M12 21c-1.8 0-3-1.4-3-3.2 0-1.6 1.2-2.8 3-4.8 1.8 2 3 3.2 3 4.8 0 1.8-1.2 3.2-3 3.2z" />
        </svg>
      );
    case "fan":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="1.8" />
          <path d="M12 10.2C12 6 10 4 7.5 4 5.6 4 4.5 5.4 4.5 7c0 2.4 3 3.8 7.5 3.2" />
          <path d="M13.8 12c4.2 0 6.2-2 6.2-4.5 0-1.9-1.4-3-3-3-2.4 0-3.8 3-3.2 7.5" opacity="0" />
          <path d="M13.8 12C18 12 20 14 20 16.5c0 1.9-1.4 3-3 3-2.4 0-3.8-3-3.2-7.5" />
          <path d="M10.2 13.8C6 14.4 4 16.4 4 18.4" opacity="0" />
          <path d="M10.5 13.5C6.6 14 4 15.6 4 18c0 1.6 1.2 2.6 2.7 2.6 2.2 0 3.6-2.6 3.8-7.1" />
        </svg>
      );
    case "train":
      return (
        <svg {...common}>
          <rect x="5" y="3.5" width="14" height="13" rx="3" />
          <path d="M5 9.5h14M9.5 13.5h.01M14.5 13.5h.01" />
          <path d="M8 17l-2 3.5M16 17l2 3.5M6.8 19h10.4" />
        </svg>
      );
    case "heart":
      return (
        <svg {...common}>
          <path d="M12 20.5C6.5 16.5 3 13.3 3 9.5 3 6.9 5 5 7.5 5c1.8 0 3.4 1 4.5 2.6C13.1 6 14.7 5 16.5 5 19 5 21 6.9 21 9.5c0 3.8-3.5 7-9 11z" />
          <path d="M6 11h3l1.5-2.5 2 4.5 1.5-2h4" />
        </svg>
      );
    case "noise":
      return (
        <svg {...common}>
          <path d="M4 12v.01M8 8.5v7M12 5.5v13M16 8.5v7M20 12v.01" />
        </svg>
      );
    case "brain":
      return (
        <svg {...common}>
          <path d="M9.5 3.5A2.8 2.8 0 0 0 6 6.2a3.2 3.2 0 0 0-2 3 3.2 3.2 0 0 0 1.2 6.1A3.3 3.3 0 0 0 8.5 20c.6 0 1-.1 1.5-.4V5.2c0-1-.6-1.7-.5-1.7z" />
          <path d="M14.5 3.5A2.8 2.8 0 0 1 18 6.2a3.2 3.2 0 0 1 2 3 3.2 3.2 0 0 1-1.2 6.1A3.3 3.3 0 0 1 15.5 20c-.6 0-1-.1-1.5-.4V5.2c0-1 .6-1.7.5-1.7z" />
        </svg>
      );
    case "piano":
      return (
        <svg {...common}>
          <rect x="3" y="4" width="18" height="16" rx="2.5" />
          <path d="M3 13h18M7.5 4v9M12 4v9M16.5 4v9" />
        </svg>
      );
    case "musicbox":
      return (
        <svg {...common}>
          <path d="M9 17.5V6.5L19 4.5v11" />
          <circle cx="6.8" cy="17.5" r="2.3" />
          <circle cx="16.8" cy="15.5" r="2.3" />
        </svg>
      );
    case "bowl":
      return (
        <svg {...common}>
          <path d="M4 10h16c0 4.5-3.2 8-8 8s-8-3.5-8-8z" />
          <path d="M9 21h6M12 18v3" />
          <path d="M5.5 6.5C7 5.5 9.4 5 12 5s5 .5 6.5 1.5" opacity="0.6" />
        </svg>
      );
    case "moon":
      return (
        <svg {...common}>
          <path d="M20 14.5A8.5 8.5 0 0 1 9.5 4 8.5 8.5 0 1 0 20 14.5z" />
        </svg>
      );
    case "mixes":
      return (
        <svg {...common}>
          <path d="M4 6h16M4 12h16M4 18h16" />
          <circle cx="9" cy="6" r="2" fill="var(--bg-1, #0b1026)" />
          <circle cx="15" cy="12" r="2" fill="var(--bg-1, #0b1026)" />
          <circle cx="7" cy="18" r="2" fill="var(--bg-1, #0b1026)" />
        </svg>
      );
    case "timer":
      return (
        <svg {...common}>
          <circle cx="12" cy="13" r="8" />
          <path d="M12 9.5V13l2.5 2M10 2.5h4" />
        </svg>
      );
    case "breathe":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="4" />
          <circle cx="12" cy="12" r="8.5" opacity="0.45" />
        </svg>
      );
    case "play":
      return (
        <svg {...common} fill="currentColor" stroke="none">
          <path d="M8 5.6v12.8c0 .9 1 1.5 1.8 1L19.4 13a1.2 1.2 0 0 0 0-2L9.8 4.6c-.8-.5-1.8.1-1.8 1z" />
        </svg>
      );
    case "pause":
      return (
        <svg {...common} fill="currentColor" stroke="none">
          <rect x="6.5" y="4.5" width="3.6" height="15" rx="1.4" />
          <rect x="13.9" y="4.5" width="3.6" height="15" rx="1.4" />
        </svg>
      );
    case "stop":
      return (
        <svg {...common} fill="currentColor" stroke="none">
          <rect x="6" y="6" width="12" height="12" rx="2.5" />
        </svg>
      );
    case "sliders":
      return (
        <svg {...common}>
          <path d="M5 6h14M5 12h14M5 18h14" opacity="0.4" />
          <circle cx="10" cy="6" r="2.4" />
          <circle cx="15" cy="12" r="2.4" />
          <circle cx="8" cy="18" r="2.4" />
        </svg>
      );
    case "close":
      return (
        <svg {...common}>
          <path d="M6.5 6.5l11 11M17.5 6.5l-11 11" />
        </svg>
      );
    case "trash":
      return (
        <svg {...common}>
          <path d="M4.5 6.5h15M9.5 6V4.5A1.5 1.5 0 0 1 11 3h2a1.5 1.5 0 0 1 1.5 1.5V6" />
          <path d="M6.5 6.5l.8 12a2 2 0 0 0 2 1.9h5.4a2 2 0 0 0 2-1.9l.8-12" />
        </svg>
      );
    case "plus":
      return (
        <svg {...common}>
          <path d="M12 5.5v13M5.5 12h13" />
        </svg>
      );
    case "headphones":
      return (
        <svg {...common}>
          <path d="M4 14v-2a8 8 0 0 1 16 0v2" />
          <rect x="3.5" y="14" width="4" height="6" rx="2" />
          <rect x="16.5" y="14" width="4" height="6" rx="2" />
        </svg>
      );
    case "sunrise":
      return (
        <svg {...common}>
          <path d="M12 3v3M5 8l2 2M19 8l-2 2M3 15h3M18 15h3M7.5 15a4.5 4.5 0 0 1 9 0" />
          <path d="M4 19h16" />
        </svg>
      );
    default:
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="8" />
        </svg>
      );
  }
}
