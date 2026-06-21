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

let _pendingEvents: AppEvent[] = [];
let _rafId: number | null = null;

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
    _pendingEvents.push(event);
    if (_rafId === null) {
      _rafId = requestAnimationFrame(() => {
        if (_pendingEvents.length === 0) { _rafId = null; return; }
        const batch = [..._pendingEvents];
        _pendingEvents = [];
        _rafId = null;
        set((state) => ({
          events: [...batch.reverse(), ...state.events].slice(0, 500),
        }));
      });
    }
  },
}));
