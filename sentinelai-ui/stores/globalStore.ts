import { create } from "zustand";

interface GlobalState {
  activeModule: string;
  setActiveModule: (m: string) => void;
}

export const useGlobalStore = create<GlobalState>((set) => ({
  activeModule: "dashboard",
  setActiveModule: (m) => set({ activeModule: m }),
}));
