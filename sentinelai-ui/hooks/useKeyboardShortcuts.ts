"use client";

import { useEffect } from "react";
import { useGlobalStore } from "@/stores/globalStore";

export function useAppKeyboardShortcuts() {
  const setActiveModule = useGlobalStore((s) => s.setActiveModule);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
      }
      if (e.key === "Escape") {
        setActiveModule("dashboard");
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [setActiveModule]);
}
