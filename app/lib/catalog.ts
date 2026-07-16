// Sound catalog and curated preset mixes for Nocturne.
// Every sound is synthesized procedurally in audio-engine.ts — no audio files.

export type Category = "nature" | "ambience" | "noise" | "brainwaves" | "melody";

export interface SoundDef {
  id: string;
  name: string;
  category: Category;
  /** Icon key rendered by components/sleep/Icon.tsx */
  icon: string;
  /** Accent hue (deg) used for the card glow when active */
  hue: number;
  defaultVolume: number; // 0..1
  headphones?: boolean; // binaural sounds need stereo separation
}

export const CATEGORIES: { id: Category | "all"; label: string }[] = [
  { id: "all", label: "All" },
  { id: "nature", label: "Nature" },
  { id: "ambience", label: "Ambience" },
  { id: "noise", label: "Noise" },
  { id: "brainwaves", label: "Brainwaves" },
  { id: "melody", label: "Melody" },
];

export const SOUNDS: SoundDef[] = [
  // Nature
  { id: "rain", name: "Rain", category: "nature", icon: "rain", hue: 210, defaultVolume: 0.7 },
  { id: "thunder", name: "Thunder", category: "nature", icon: "thunder", hue: 260, defaultVolume: 0.6 },
  { id: "ocean", name: "Ocean Waves", category: "nature", icon: "ocean", hue: 195, defaultVolume: 0.7 },
  { id: "stream", name: "Creek", category: "nature", icon: "stream", hue: 175, defaultVolume: 0.6 },
  { id: "wind", name: "Wind", category: "nature", icon: "wind", hue: 150, defaultVolume: 0.6 },
  { id: "birds", name: "Morning Birds", category: "nature", icon: "bird", hue: 90, defaultVolume: 0.5 },
  { id: "crickets", name: "Night Crickets", category: "nature", icon: "cricket", hue: 120, defaultVolume: 0.45 },
  { id: "fire", name: "Campfire", category: "nature", icon: "fire", hue: 25, defaultVolume: 0.65 },

  // Ambience
  { id: "fan", name: "Fan", category: "ambience", icon: "fan", hue: 200, defaultVolume: 0.6 },
  { id: "train", name: "Night Train", category: "ambience", icon: "train", hue: 280, defaultVolume: 0.55 },
  { id: "heartbeat", name: "Heartbeat", category: "ambience", icon: "heart", hue: 340, defaultVolume: 0.55 },

  // Noise
  { id: "white", name: "White Noise", category: "noise", icon: "noise", hue: 220, defaultVolume: 0.4 },
  { id: "pink", name: "Pink Noise", category: "noise", icon: "noise", hue: 320, defaultVolume: 0.45 },
  { id: "brown", name: "Brown Noise", category: "noise", icon: "noise", hue: 20, defaultVolume: 0.55 },

  // Brainwaves (binaural beats — headphones recommended)
  { id: "delta", name: "Delta · Deep Sleep", category: "brainwaves", icon: "brain", hue: 250, defaultVolume: 0.35, headphones: true },
  { id: "theta", name: "Theta · Dream", category: "brainwaves", icon: "brain", hue: 270, defaultVolume: 0.35, headphones: true },
  { id: "alpha", name: "Alpha · Relax", category: "brainwaves", icon: "brain", hue: 290, defaultVolume: 0.35, headphones: true },

  // Melody (generative — never repeats)
  { id: "piano", name: "Dream Piano", category: "melody", icon: "piano", hue: 230, defaultVolume: 0.5 },
  { id: "musicbox", name: "Music Box", category: "melody", icon: "musicbox", hue: 45, defaultVolume: 0.45 },
  { id: "bowl", name: "Singing Bowl", category: "melody", icon: "bowl", hue: 160, defaultVolume: 0.5 },
];

export const SOUND_BY_ID: Record<string, SoundDef> = Object.fromEntries(
  SOUNDS.map((s) => [s.id, s])
);

export interface Preset {
  id: string;
  name: string;
  tagline: string;
  sounds: Record<string, number>; // soundId -> volume
  hues: [number, number]; // gradient for the card
}

export const PRESETS: Preset[] = [
  {
    id: "deep-sleep",
    name: "Deep Sleep",
    tagline: "Brown noise, soft rain & delta waves",
    sounds: { brown: 0.5, rain: 0.45, delta: 0.3 },
    hues: [250, 210],
  },
  {
    id: "rainy-cabin",
    name: "Rainy Cabin",
    tagline: "Rain on the roof beside a crackling fire",
    sounds: { rain: 0.65, fire: 0.5, thunder: 0.35 },
    hues: [215, 25],
  },
  {
    id: "ocean-night",
    name: "Ocean Night",
    tagline: "Waves rolling under a starry sky",
    sounds: { ocean: 0.7, wind: 0.3, crickets: 0.25 },
    hues: [195, 250],
  },
  {
    id: "forest-dawn",
    name: "Forest Dawn",
    tagline: "Birdsong over a gentle creek",
    sounds: { birds: 0.5, stream: 0.55, wind: 0.25 },
    hues: [95, 170],
  },
  {
    id: "dreamscape",
    name: "Dreamscape",
    tagline: "Floating piano with theta waves",
    sounds: { piano: 0.55, theta: 0.3, wind: 0.2 },
    hues: [230, 280],
  },
  {
    id: "baby-lullaby",
    name: "Lullaby",
    tagline: "Music box over a calm heartbeat",
    sounds: { musicbox: 0.5, heartbeat: 0.4, pink: 0.25 },
    hues: [45, 340],
  },
  {
    id: "zen-temple",
    name: "Zen Temple",
    tagline: "Singing bowls in mountain air",
    sounds: { bowl: 0.55, wind: 0.35, alpha: 0.25 },
    hues: [160, 200],
  },
  {
    id: "night-express",
    name: "Night Express",
    tagline: "Sleeper train through the rain",
    sounds: { train: 0.55, rain: 0.4, brown: 0.3 },
    hues: [280, 215],
  },
];
