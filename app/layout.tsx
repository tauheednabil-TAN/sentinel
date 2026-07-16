import type { Metadata, Viewport } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Nocturne — Sleep Sounds & Relaxation",
  description:
    "Mix endless generated soundscapes, set a fading sleep timer, plan sleep cycles and breathe your way to rest.",
  applicationName: "Nocturne",
  appleWebApp: {
    capable: true,
    statusBarStyle: "black-translucent",
    title: "Nocturne",
  },
  formatDetection: { telephone: false },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
  userScalable: false,
  viewportFit: "cover",
  themeColor: [
    { media: "(prefers-color-scheme: dark)", color: "#05070f" },
    { media: "(prefers-color-scheme: light)", color: "#dfe3f5" },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
