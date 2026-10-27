import type { Config } from "tailwindcss";

const v = (name: string) => `var(--${name})`;

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        page: v("page"), surface: v("surface"), ink: v("ink"), ink2: v("ink2"), muted: v("muted"),
        line: v("line"), accent: v("accent"), "accent-ink": v("accent-ink"),
        good: v("good"), bad: v("bad"), warn: v("warn"),
      },
    },
  },
  plugins: [],
};

export default config;
