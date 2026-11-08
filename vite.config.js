import { fileURLToPath, URL } from "node:url";

import { defineConfig } from "vite";

const apiTarget = process.env.AGENTFENCE_API_URL || "http://127.0.0.1:8080";

const proxy = {
  "/v1": apiTarget,
  "/healthz": apiTarget,
  "/docs": apiTarget,
  "/openapi.json": apiTarget,
  "/redoc": apiTarget,
};

export default defineConfig({
  root: fileURLToPath(new URL("./frontend", import.meta.url)),
  publicDir: false,
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy,
  },
  preview: {
    host: "127.0.0.1",
    port: 4173,
    strictPort: true,
    proxy,
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
