import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Placeholder palette; replaced when the design system lands in M2.
        brand: { DEFAULT: "#0f766e", dark: "#115e59" },
      },
    },
  },
  plugins: [],
};

export default config;
