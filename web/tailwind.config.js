/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#08111D",
        surface: "#101D2D",
        surfaceBorder: "#24354B",
        primary: {
          DEFAULT: "#2BB7A9",
          hover: "#1F9B90",
        },
        success: "#10b981",
        warning: "#f59e0b",
        danger: "#ef4444",
        muted: "#94a3b8",
        soc: {
          bg: "#08111D",
          surface: "#101D2D",
          "surface-2": "#142438",
          "surface-3": "#1B3048",
          border: "#24354B",
          "border-light": "#36516C",
          "border-hover": "#4B6A87",
        },
        accent: {
          DEFAULT: "#2BB7A9",
          hover: "#1F9B90",
          muted: "#176A68",
        },
        severity: {
          clean: "#10B981",
          "clean-bg": "#064E3B",
          "clean-border": "#065F46",
          suspicious: "#F59E0B",
          "suspicious-bg": "#78350F",
          "suspicious-border": "#92400E",
          high: "#F97316",
          "high-bg": "#7C2D12",
          "high-border": "#9A3412",
          critical: "#EF4444",
          "critical-bg": "#7F1D1D",
          "critical-border": "#991B1B",
        },
        status: {
          connected: "#10B981",
          monitoring: "#3B82F6",
          processing: "#F59E0B",
          error: "#EF4444",
          offline: "#6B7280",
          info: "#06B6D4",
        },
      },
      fontFamily: {
        sans: ["DM Sans", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
      fontSize: {
        xs: ["0.75rem", { lineHeight: "1.1rem" }],
        sm: ["0.8125rem", { lineHeight: "1.25rem" }],
        base: ["0.875rem", { lineHeight: "1.35rem" }],
        lg: ["1rem", { lineHeight: "1.5rem" }],
        xl: ["1.125rem", { lineHeight: "1.65rem" }],
        "2xl": ["1.375rem", { lineHeight: "1.85rem" }],
        "3xl": ["1.75rem", { lineHeight: "2.25rem" }],
        "4xl": ["2.25rem", { lineHeight: "2.5rem" }],
      },
      spacing: {
        18: "4.5rem",
      },
      animation: {
        "fade-in": "fadeIn 0.2s ease-out",
        "slide-in": "slideIn 0.25s ease-out",
        "slide-up": "slideUp 0.25s ease-out",
        "pulse-soft": "pulseSoft 2s ease-in-out infinite",
        shimmer: "shimmer 1.5s linear infinite",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        slideIn: {
          "0%": { transform: "translateX(-100%)", opacity: "0" },
          "100%": { transform: "translateX(0)", opacity: "1" },
        },
        slideUp: {
          "0%": { transform: "translateY(8px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
        pulseSoft: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.5" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
      },
    },
  },
  plugins: [],
};
