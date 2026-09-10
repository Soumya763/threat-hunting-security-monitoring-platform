import { createContext, useContext, useEffect, useState } from "react";
import { getHealth } from "../services/api";

const POLL_INTERVAL_MS = 15000;

const HealthContext = createContext(null);

// Derives a single "operational" | "degraded" | "down" status from the
// real /health response ({api, postgres, elasticsearch}, each "ok" or an
// error string) so Header/Sidebar don't each re-implement this logic.
function deriveStatus(data) {
  const values = [data.api, data.postgres, data.elasticsearch];
  if (values.every((v) => v === "ok")) return "operational";
  return "degraded";
}

export function HealthProvider({ children }) {
  const [state, setState] = useState({ status: "loading", loading: true, error: null });

  useEffect(() => {
    let cancelled = false;

    const poll = () => {
      getHealth()
        .then((data) => {
          if (cancelled) return;
          setState({ status: deriveStatus(data), loading: false, error: null });
        })
        .catch(() => {
          if (cancelled) return;
          setState({ status: "down", loading: false, error: "Unable to reach the API" });
        });
    };

    poll();
    const interval = setInterval(poll, POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  return <HealthContext.Provider value={state}>{children}</HealthContext.Provider>;
}

export function useHealth() {
  const ctx = useContext(HealthContext);
  if (!ctx) {
    throw new Error("useHealth must be used within a HealthProvider");
  }
  return ctx;
}
