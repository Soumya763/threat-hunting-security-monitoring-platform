import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Minimal Vite config - just the React plugin. No API proxy or other
// config yet since the services/ layer isn't built out.
export default defineConfig({
  plugins: [react()],
});
