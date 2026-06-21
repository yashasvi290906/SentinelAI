import { create } from "zustand";

export type EventType = "prediction" | "compare" | "system" | "error" | "user_action";

export interface AppEvent {
  id: string;
  timestamp: string;
  type: EventType;
  message: string;
  details?: Record<string, unknown>;
}

interface EventState {
  events: AppEvent[];
  addEvent: (type: EventType, message: string, details?: Record<string, unknown>) => void;
}

function generateId(): string {
  return `evt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

export const useEventStore = create<EventState>((set) => ({
  events: [],

  addEvent: (type, message, details) => {
    const event: AppEvent = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      type,
      message,
      details,
    };
    set((state) => ({
      events: [event, ...state.events].slice(0, 500),
    }));
  },
}));
