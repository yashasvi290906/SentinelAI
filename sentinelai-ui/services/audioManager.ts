"use client";

interface AudioPreferences {
  enabled: boolean;
  volume: number;
  threatDetected: boolean;
  criticalThreat: boolean;
  reportGenerated: boolean;
  simulationComplete: boolean;
  backendOffline: boolean;
  backendReconnected: boolean;
  notificationPing: boolean;
}

type SoundName = keyof AudioPreferences;

type SoundGenerator = (
  ctx: AudioContext,
  master: GainNode,
) => { nodes: AudioNode[]; duration: number };

class AudioManager {
  private ctx: AudioContext | null = null;
  private masterGain: GainNode | null = null;
  private currentNodes: AudioNode[] = [];
  private initialized = false;
  private muted = false;

  private preferences: AudioPreferences = {
    enabled: true,
    volume: 0.6,
    threatDetected: true,
    criticalThreat: true,
    reportGenerated: true,
    simulationComplete: true,
    backendOffline: true,
    backendReconnected: true,
    notificationPing: true,
  };

  private generators: Record<Exclude<SoundName, "enabled" | "volume">, SoundGenerator> = {
    threatDetected: (ctx, master) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.value = 800;
      gain.gain.setValueAtTime(0.4, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.15);
      osc.connect(gain);
      gain.connect(master);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.15);
      return { nodes: [osc, gain], duration: 150 };
    },

    criticalThreat: (ctx, master) => {
      const duration = 0.3;
      const osc1 = ctx.createOscillator();
      const osc2 = ctx.createOscillator();
      const gain1 = ctx.createGain();
      const gain2 = ctx.createGain();

      osc1.type = "sine";
      osc1.frequency.value = 600;
      osc2.type = "sine";
      osc2.frequency.value = 900;

      gain1.gain.setValueAtTime(0.5, ctx.currentTime);
      gain1.gain.setValueAtTime(0.001, ctx.currentTime + 0.1);
      gain1.gain.setValueAtTime(0.5, ctx.currentTime + 0.15);
      gain1.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);

      gain2.gain.setValueAtTime(0.001, ctx.currentTime);
      gain2.gain.setValueAtTime(0.5, ctx.currentTime + 0.05);
      gain2.gain.setValueAtTime(0.001, ctx.currentTime + 0.12);
      gain2.gain.setValueAtTime(0.5, ctx.currentTime + 0.18);
      gain2.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);

      osc1.connect(gain1);
      osc2.connect(gain2);
      gain1.connect(master);
      gain2.connect(master);
      osc1.start(ctx.currentTime);
      osc1.stop(ctx.currentTime + duration);
      osc2.start(ctx.currentTime);
      osc2.stop(ctx.currentTime + duration);
      return { nodes: [osc1, osc2, gain1, gain2], duration: duration * 1000 };
    },

    reportGenerated: (ctx, master) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.setValueAtTime(523, ctx.currentTime);
      osc.frequency.setValueAtTime(659, ctx.currentTime + 0.2);
      gain.gain.setValueAtTime(0.3, ctx.currentTime);
      gain.gain.setValueAtTime(0.3, ctx.currentTime + 0.35);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.4);
      osc.connect(gain);
      gain.connect(master);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.4);
      return { nodes: [osc, gain], duration: 400 };
    },

    simulationComplete: (ctx, master) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.setValueAtTime(440, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.25);
      gain.gain.setValueAtTime(0.35, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.25);
      osc.connect(gain);
      gain.connect(master);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.25);
      return { nodes: [osc, gain], duration: 250 };
    },

    backendOffline: (ctx, master) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(440, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(220, ctx.currentTime + 0.4);
      gain.gain.setValueAtTime(0.25, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.4);
      osc.connect(gain);
      gain.connect(master);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.4);
      return { nodes: [osc, gain], duration: 400 };
    },

    backendReconnected: (ctx, master) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.setValueAtTime(220, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.3);
      gain.gain.setValueAtTime(0.35, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
      osc.connect(gain);
      gain.connect(master);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.3);
      return { nodes: [osc, gain], duration: 300 };
    },

    notificationPing: (ctx, master) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.value = 1000;
      gain.gain.setValueAtTime(0.15, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.08);
      osc.connect(gain);
      gain.connect(master);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.08);
      return { nodes: [osc, gain], duration: 80 };
    },
  };

  init(): void {
    if (this.initialized) return;
    this.ctx = new AudioContext();
    this.masterGain = this.ctx.createGain();
    this.masterGain.gain.value = this.preferences.volume;
    this.masterGain.connect(this.ctx.destination);
    this.initialized = true;
  }

  play(soundName: SoundName): void {
    if (!this.initialized || !this.ctx || !this.masterGain) return;
    if (!this.preferences.enabled) return;
    if (soundName === "enabled" || soundName === "volume") return;
    if (!this.preferences[soundName]) return;
    if (this.muted) return;

    this.stopCurrent();

    const gen = this.generators[soundName];
    if (!gen) return;

    const result = gen(this.ctx, this.masterGain);
    this.currentNodes = result.nodes;

    setTimeout(() => this.stopCurrent(), result.duration + 50);
  }

  setVolume(vol: number): void {
    const clamped = Math.max(0, Math.min(1, vol));
    this.preferences.volume = clamped;
    if (this.masterGain) {
      this.masterGain.gain.setValueAtTime(clamped, this.ctx!.currentTime);
    }
  }

  setMuted(muted: boolean): void {
    this.muted = muted;
    if (muted) this.stopCurrent();
  }

  setPreference(key: SoundName, value: boolean): void {
    if (key === "enabled" || key === "volume") return;
    this.preferences[key] = value;
  }

  getPreferences(): AudioPreferences {
    return { ...this.preferences };
  }

  setPreferences(prefs: Partial<AudioPreferences>): void {
    Object.assign(this.preferences, prefs);
    if (prefs.volume !== undefined) this.setVolume(prefs.volume);
  }

  private stopCurrent(): void {
    this.currentNodes.forEach((node) => {
      try {
        if (node instanceof OscillatorNode || node instanceof GainNode) {
          node.disconnect();
        }
      } catch {}
    });
    this.currentNodes = [];
  }
}

export const audioManager = new AudioManager();
