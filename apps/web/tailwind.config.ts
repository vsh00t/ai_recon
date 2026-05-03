import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: {
          0: "var(--bg-0)",
          1: "var(--bg-1)",
          2: "var(--bg-2)",
          3: "var(--bg-3)",
        },
        fg: {
          muted: "var(--fg-muted)",
          DEFAULT: "var(--fg-default)",
          bold: "var(--fg-bold)",
        },
        border: {
          subtle: "var(--border-subtle)",
          strong: "var(--border-strong)",
        },
        accent: {
          DEFAULT: "var(--accent)",
          fg: "var(--accent-fg)",
          subtle: "var(--accent-subtle)",
        },
        sev: {
          critical: "var(--sev-critical)",
          high: "var(--sev-high)",
          medium: "var(--sev-medium)",
          low: "var(--sev-low)",
          info: "var(--sev-info)",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      borderRadius: {
        sm: "4px",
        md: "6px",
        lg: "8px",
        xl: "12px",
        "2xl": "16px",
      },
      boxShadow: {
        sm: "0 1px 2px rgba(0,0,0,.4)",
        md: "0 4px 12px rgba(0,0,0,.35)",
        lg: "0 12px 32px rgba(0,0,0,.45)",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0", transform: "translateY(2px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        pulse: {
          "0%,100%": { opacity: "1" },
          "50%": { opacity: ".5" },
        },
      },
      animation: {
        "fade-in": "fade-in .12s cubic-bezier(.2,0,0,1)",
        pulse: "pulse 1.6s cubic-bezier(.4,0,.6,1) infinite",
      },
    },
  },
  plugins: [],
};
export default config;
