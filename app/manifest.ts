import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Nocturne — Sleep Sounds & Relaxation",
    short_name: "Nocturne",
    description:
      "Mix endless generated soundscapes, set a fading sleep timer, plan sleep cycles and breathe your way to rest.",
    start_url: "/",
    display: "standalone",
    orientation: "portrait",
    background_color: "#05070f",
    theme_color: "#05070f",
    icons: [
      { src: "/icon", sizes: "512x512", type: "image/png" },
      { src: "/apple-icon", sizes: "180x180", type: "image/png" },
    ],
  };
}
