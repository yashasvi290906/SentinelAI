'use client';

import { useAppKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts';

export function KeyboardShortcutsProvider() {
  useAppKeyboardShortcuts();
  return null;
}
