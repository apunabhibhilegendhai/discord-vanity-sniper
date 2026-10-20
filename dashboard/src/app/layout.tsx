import type { Metadata } from "next";
import Link from "next/link";
import { LogoutButton } from "@/components/LogoutButton";
import "./globals.css";

export const metadata: Metadata = {
  title: "Sniper dashboard",
  description: "Config, status, and issues for the Discord vanity sniper and Vanity Guard.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <header className="topbar">
            <div className="brand">
              <span className="brand-mark" aria-hidden="true" />
              <span>Sniper control</span>
            </div>
            <nav className="nav" aria-label="Dashboard">
              <Link href="/">Overview</Link>
              <Link href="/config">Config</Link>
              <Link href="/issues">Issues</Link>
            </nav>
            <LogoutButton />
          </header>
          <main>{children}</main>
        </div>
      </body>
    </html>
  );
}
