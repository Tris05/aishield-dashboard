import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AIShield Dashboard",
  description: "AI and software security scan reports with human-reviewed remediation.",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
