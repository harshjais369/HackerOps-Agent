import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "HackerOps Agent | Autonomous Web Vulnerability Assessment & Auto-Remediation",
  description: "Closed-loop cybersecurity agent for autonomous reconnaissance, attack graph reasoning, and defensive patch generation.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#0B0F19] text-gray-100 min-h-screen selection:bg-emerald-500 selection:text-black">
        {children}
      </body>
    </html>
  );
}
