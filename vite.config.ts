import { defineConfig } from "vite";

// Builds the web playground (web/) into docs/ for free GitHub Pages hosting.
// `base: "./"` keeps asset URLs relative so it works at /jwtlens/ on Pages.
export default defineConfig({
  root: "web",
  base: "./",
  build: {
    outDir: "../docs",
    emptyOutDir: true,
    target: "es2022",
  },
  server: {
    fs: { allow: [".."] },
  },
});
