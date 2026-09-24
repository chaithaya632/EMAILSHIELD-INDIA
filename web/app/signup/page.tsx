// web/app/signup/page.tsx
"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { ShieldCheck, Lock, Mail, User, ArrowRight, CheckCircle2 } from "lucide-react";

export default function SignUpPage() {
  const router = useRouter();
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setInfoMessage(null);

    // Client-side validation
    const emailTrim = email.trim();
    if (!emailTrim || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailTrim)) {
      setError("Enter a valid email address.");
      return;
    }

    if (!password) {
      setError("Password is required.");
      return;
    }

    if (!confirmPassword) {
      setError("Please confirm your password.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);

    try {
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          fullName: fullName.trim(),
          email: emailTrim,
          password,
          confirmPassword,
        }),
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        setError(data.error?.message || "Unable to create your account right now. Please try again.");
      } else {
        if (data.data?.session_created) {
          // Direct session established
          router.push("/dashboard");
          router.refresh();
        } else {
          // Email confirmation required
          setInfoMessage(
            data.data?.message ||
              "Account created. Please check your email to confirm your account before logging in."
          );
        }
      }
    } catch {
      setError("Unable to create your account right now. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex-1 flex items-center justify-center p-6 bg-soc-bg">
      <div className="w-full max-w-md bg-soc-surface border border-soc-border rounded-xl p-8 shadow-2xl animate-fade-in">
        <div className="text-center mb-8">
          <div className="inline-flex p-3 bg-accent/10 border border-accent/20 rounded-xl mb-3 text-accent">
            <ShieldCheck className="w-8 h-8" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white font-mono">
            EMAILSHIELD <span className="text-accent">INDIA</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono uppercase tracking-wider">
            Investigator Account Registration
          </p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-severity-critical-bg/40 border border-severity-critical-border rounded-lg text-severity-critical text-xs font-medium">
            {error}
          </div>
        )}

        {infoMessage && (
          <div className="mb-6 p-4 bg-accent/10 border border-accent/30 rounded-lg text-accent text-xs font-medium flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
            <div>
              <p>{infoMessage}</p>
              <div className="mt-3">
                <Link
                  href="/login"
                  className="inline-flex items-center text-xs font-semibold text-accent hover:underline"
                >
                  Proceed to Login →
                </Link>
              </div>
            </div>
          </div>
        )}

        {!infoMessage && (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 font-mono">
                Full Name
              </label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-500 absolute left-3 top-3.5" />
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Officer / Analyst Name"
                  className="w-full pl-10 pr-4 py-2.5 bg-soc-surface-2 border border-soc-border rounded-lg text-sm text-white focus:outline-none focus:border-accent font-mono transition-colors"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 font-mono">
                Email Address
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-3.5" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="investigator@agency.gov.in"
                  className="w-full pl-10 pr-4 py-2.5 bg-soc-surface-2 border border-soc-border rounded-lg text-sm text-white focus:outline-none focus:border-accent font-mono transition-colors"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 font-mono">
                Password
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-3.5" />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-10 pr-4 py-2.5 bg-soc-surface-2 border border-soc-border rounded-lg text-sm text-white focus:outline-none focus:border-accent font-mono transition-colors"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 font-mono">
                Confirm Password
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-3.5" />
                <input
                  type="password"
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-10 pr-4 py-2.5 bg-soc-surface-2 border border-soc-border rounded-lg text-sm text-white focus:outline-none focus:border-accent font-mono transition-colors"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-accent hover:bg-accent-hover text-[#06141A] font-semibold rounded-lg text-sm transition-colors flex items-center justify-center gap-2 mt-6 shadow-lg shadow-accent/10 disabled:opacity-50"
            >
              {loading ? "Creating Account..." : "Create Account"}
              {!loading && <ArrowRight className="w-4 h-4" />}
            </button>
          </form>
        )}

        <div className="mt-6 pt-4 border-t border-soc-border text-center">
          <p className="text-xs text-slate-400">
            Already have an account?{" "}
            <Link href="/login" className="text-accent hover:underline font-semibold">
              Login
            </Link>
          </p>
        </div>

        <div className="mt-4 pt-4 border-t border-soc-border/50 text-center">
          <p className="text-[0.6875rem] text-slate-500 font-mono">
            Government of India Cyber Defense Framework Compliant.
          </p>
        </div>
      </div>
    </div>
  );
}
