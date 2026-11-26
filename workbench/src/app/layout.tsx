import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ServiceCore Review Workbench",
  description:
    "Evidence-bound WCAG 2.2 AA & AODA compliance review and cryptographic sign-off workbench.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-[var(--bg-canvas)] text-[var(--ink-primary)] antialiased">
        <a href="#main-content" className="skip-link">
          Skip to main content
        </a>
        {children}
      </body>
    </html>
  );
}
