import { create } from "zustand";
import type { Notification } from "@/lib/types";

const STORAGE_KEY = "sentinelai_notifications";
const MAX_NOTIFICATIONS = 200;

function loadFromStorage(): Notification[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function persist(notifications: Notification[]): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(notifications));
  } catch {
    // silently fail if storage is full
  }
}

interface NotificationState {
  notifications: Notification[];
  addNotification: (n: Omit<Notification, "id" | "timestamp" | "read">) => void;
  addSystemNotification: (title: string, message: string, type?: Notification["type"]) => void;
  scheduleDismiss: (id: string, type: string) => void;
  markRead: (id: string) => void;
  markAllRead: () => void;
  deleteNotification: (id: string) => void;
  clearAll: () => void;
  getByType: (type: Notification["type"]) => Notification[];
  getUnread: () => Notification[];
  unreadCount: () => number;
}

let counter = 0;

export const useNotificationStore = create<NotificationState>((set, get) => ({
  notifications: loadFromStorage(),

  addNotification: (n) => {
    counter++;
    const notification: Notification = {
      ...n,
      id: `notif-${Date.now()}-${counter}`,
      timestamp: new Date().toISOString(),
      read: false,
    };
    const updated = [notification, ...get().notifications].slice(0, MAX_NOTIFICATIONS);
    persist(updated);
    set({ notifications: updated });
    get().scheduleDismiss(notification.id, notification.type);
  },

  addSystemNotification: (title, message, type = "info") => {
    get().addNotification({ type, title, message });
  },

  scheduleDismiss: (id, type) => {
    const delay = type === "error" ? 12000 : type === "warning" ? 8000 : 5000;
    setTimeout(() => {
      useNotificationStore.getState().deleteNotification(id);
    }, delay);
  },

  markRead: (id) => {
    const updated = get().notifications.map((n) =>
      n.id === id ? { ...n, read: true } : n
    );
    persist(updated);
    set({ notifications: updated });
  },

  markAllRead: () => {
    const updated = get().notifications.map((n) => ({ ...n, read: true }));
    persist(updated);
    set({ notifications: updated });
  },

  deleteNotification: (id) => {
    const updated = get().notifications.filter((n) => n.id !== id);
    persist(updated);
    set({ notifications: updated });
  },

  clearAll: () => {
    persist([]);
    set({ notifications: [] });
  },

  getByType: (type) => {
    return get().notifications.filter((n) => n.type === type);
  },

  getUnread: () => {
    return get().notifications.filter((n) => !n.read);
  },

  unreadCount: () => {
    return get().notifications.filter((n) => !n.read).length;
  },
}));
