// web/app/layout.tsx
import "@/styles/globals.css";
import type { Metadata } from "next";
import Sidebar from "@/components/Sidebar";
import { ToastProvider } from "@/components/ui/Toast";

export const metadata: Metadata = {
  title: "EMAILSHIELD INDIA — Autonomous Email Forensics & Threat Intelligence",
  description: "Next-generation autonomous security operations platform for email threat detection, forensic analysis, and Incident response.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-soc-bg text-slate-100 flex min-h-screen">
        <ToastProvider>
          <Sidebar />
          <main className="flex-1 flex flex-col min-w-0 overflow-y-auto">
            {children}
          </main>
        </ToastProvider>
      </body>
    </html>
  );
}
