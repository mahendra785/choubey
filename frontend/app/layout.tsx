import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "PromptShield",
  description: "Prompt-injection testbed with a conformal-gated defense cascade",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-page text-ink antialiased">{children}</body>
    </html>
  );
}
