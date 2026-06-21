import type { Metadata } from "next";
import { Sora } from "next/font/google";
import "./globals.css";
import { KeyboardShortcutsProvider } from "@/components/providers/KeyboardShortcutsProvider";

const sora = Sora({
  subsets: ["latin"],
  variable: "--font-sora",
  display: "swap",
  weight: ["300", "400", "500", "600", "700"],
});

export const metadata: Metadata = {
  title: "SENTINEL AI — Enterprise Security Systems",
  description:
    "Enterprise security systems built in days. AI-powered surveillance deployed with zero-trust architecture. Smart access control set up for your entire facility.",
  keywords: ["security", "AI", "surveillance", "zero-trust", "access control", "enterprise security"],
  authors: [{ name: "Sentinel AI" }],
  robots: "noindex",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${sora.variable} h-full`}>
      <head>
        <meta name="theme-color" content="#0a0a0a" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link rel="apple-touch-icon" href="/icons/icon-192.png" />
      </head>
      <body className="h-full antialiased font-sora">
        <KeyboardShortcutsProvider />
        {children}
        <script dangerouslySetInnerHTML={{ __html: `
          if ('serviceWorker' in navigator) {
            navigator.serviceWorker.getRegistrations().then(function(r) {
              for (var i = 0; i < r.length; i++) r[i].unregister();
            });
          }
          try { localStorage.removeItem('sentinelai_notifications'); } catch(e) {}
        ` }} />
      </body>
    </html>
  );
}
