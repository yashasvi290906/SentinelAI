"use client";

import { useEffect, useRef } from "react";
import { useSystemStore } from "@/stores/systemStore";
import { HEALTH_POLL_INTERVAL } from "@/lib/config";

export function useHealthPolling() {
  const checkHealthRef = useRef(useSystemStore.getState().checkHealth);

  useEffect(() => {
    checkHealthRef.current();
    const interval = setInterval(() => {
      checkHealthRef.current();
    }, HEALTH_POLL_INTERVAL);
    return () => clearInterval(interval);
  }, []);
}
