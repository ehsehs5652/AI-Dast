import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 4173,
    strictPort: true,
    // The delivery workspace is on a Windows-mounted filesystem under WSL.
    watch: { usePolling: true, interval: 500 },
  },
});
