import type { Metadata, Viewport } from "next";
import localFont from "next/font/local";

import "./console.css";
import { themeInitScript } from "@/lib/theme-script";

// Pretendard (SIL Open Font License 1.1, fonts/Pretendard-LICENSE.txt), KS X 1001 subset.
const pretendard = localFont({
  src: [
    { path: "./fonts/Pretendard-Regular.subset.woff2", weight: "400", style: "normal" },
    { path: "./fonts/Pretendard-Medium.subset.woff2", weight: "500", style: "normal" },
    { path: "./fonts/Pretendard-SemiBold.subset.woff2", weight: "600", style: "normal" },
  ],
  variable: "--font-pretendard",
  display: "swap",
  fallback: ["-apple-system", "Apple SD Gothic Neo", "Noto Sans KR", "Malgun Gothic", "sans-serif"],
});

export const metadata: Metadata = {
  title: "CreMore",
  description: "Credential inventory, exposure and remediation across cloud, code and SaaS",
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f3f6fb" },
    { media: "(prefers-color-scheme: dark)", color: "#0c1116" },
  ],
};

export default function ConsoleLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  // The inline script applies a saved theme before paint; React keeps that attribute.
  return <html lang="ko" className={pretendard.variable} suppressHydrationWarning>
    <head><script dangerouslySetInnerHTML={{ __html: themeInitScript }} /></head>
    <body>{children}</body>
  </html>;
}
