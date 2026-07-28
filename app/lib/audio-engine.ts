// Procedural sound-synthesis engine built on the Web Audio API.
// Every soundscape is generated mathematically at runtime — no samples, no
// downloads, infinite non-looping audio. Each builder wires an isolated node
// graph into a per-sound gain, all summed into a master gain.
//
// Output path: master -> MediaStreamDestination -> <audio> element when the
// browser allows it (keeps iOS Safari playing with the screen locked and
// enables lock-screen media controls); falls back to ctx.destination.

type Cleanup = () => void;

interface ActiveSound {
  gain: GainNode;
  cleanup: Cleanup;
}

export type EngineListener = () => void;

const RAMP = 0.08; // s, click-free volume changes

export class AudioEngine {
  private ctx: AudioContext | null = null;
  private master: GainNode | null = null;
  private outputEl: HTMLAudioElement | null = null;
  private active = new Map<string, ActiveSound>();
  private noiseBuffers = new Map<string, AudioBuffer>();
  private listeners = new Set<EngineListener>();
  private masterVolume = 1;
  private suspended = false;

  // ---- lifecycle -----------------------------------------------------------

  private async ensureContext(): Promise<AudioContext> {
    if (!this.ctx) {
      const Ctor =
        window.AudioContext ??
        (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
      this.ctx = new Ctor();
      this.master = this.ctx.createGain();
      this.master.gain.value = this.masterVolume;
      await this.routeOutput();
      this.installMediaSession();
    }
    if (this.ctx.state === "suspended" && !this.suspended) {
      await this.ctx.resume().catch(() => {});
    }
    return this.ctx;
  }

  /** Prefer an <audio> element fed by a MediaStream so iOS keeps playing when
   *  the screen locks; otherwise connect straight to the speakers. */
  private async routeOutput() {
    const ctx = this.ctx!;
    const master = this.master!;
    try {
      const streamDest = ctx.createMediaStreamDestination();
      master.connect(streamDest);
      const el = new Audio();
      el.srcObject = streamDest.stream;
      el.setAttribute("playsinline", "true");
      el.loop = false;
      await el.play();
      this.outputEl = el;
    } catch {
      this.outputEl = null;
      master.connect(ctx.destination);
    }
  }

  private installMediaSession() {
    if (!("mediaSession" in navigator)) return;
    try {
      navigator.mediaSession.metadata = new MediaMetadata({
        title: "Nocturne",
        artist: "Sleep sounds & relaxation",
      });
      navigator.mediaSession.setActionHandler("play", () => void this.resume());
      navigator.mediaSession.setActionHandler("pause", () => void this.pause());
    } catch {
      // media session is best-effort
    }
  }

  // ---- public state --------------------------------------------------------

  subscribe(fn: EngineListener): Cleanup {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private emit() {
    this.listeners.forEach((fn) => fn());
  }

  get activeIds(): string[] {
    return [...this.active.keys()];
  }

  get isPaused(): boolean {
    return this.suspended;
  }

  isActive(id: string): boolean {
    return this.active.has(id);
  }

  // ---- transport -----------------------------------------------------------

  async start(id: string, volume: number) {
    const ctx = await this.ensureContext();
    if (this.active.has(id)) return;
    const gain = ctx.createGain();
    gain.gain.setValueAtTime(0.0001, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(Math.max(volume, 0.0001), ctx.currentTime + 0.4);
    gain.connect(this.master!);
    const cleanup = this.build(id, ctx, gain);
    this.active.set(id, { gain, cleanup });
    if (this.suspended) await this.resume();
    this.emit();
  }

  stop(id: string) {
    const sound = this.active.get(id);
    if (!sound || !this.ctx) return;
    const t = this.ctx.currentTime;
    sound.gain.gain.cancelScheduledValues(t);
    sound.gain.gain.setValueAtTime(Math.max(sound.gain.gain.value, 0.0001), t);
    sound.gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.3);
    const { cleanup, gain } = sound;
    this.active.delete(id);
    window.setTimeout(() => {
      cleanup();
      gain.disconnect();
    }, 400);
    this.emit();
  }

  stopAll() {
    [...this.active.keys()].forEach((id) => this.stop(id));
  }

  setVolume(id: string, volume: number) {
    const sound = this.active.get(id);
    if (!sound || !this.ctx) return;
    const t = this.ctx.currentTime;
    sound.gain.gain.cancelScheduledValues(t);
    sound.gain.gain.setTargetAtTime(Math.max(volume, 0.0001), t, RAMP);
  }

  setMasterVolume(volume: number) {
    this.masterVolume = volume;
    if (this.master && this.ctx) {
      this.master.gain.setTargetAtTime(Math.max(volume, 0.0001), this.ctx.currentTime, RAMP);
    }
  }

  async pause() {
    if (!this.ctx) return;
    this.suspended = true;
    await this.ctx.suspend().catch(() => {});
    this.emit();
  }

  async resume() {
    if (!this.ctx) return;
    this.suspended = false;
    await this.ctx.resume().catch(() => {});
    this.outputEl?.play().catch(() => {});
    this.emit();
  }

  /** Sleep-timer fade: glide the master gain to silence over `seconds`. */
  fadeOut(seconds: number) {
    if (!this.master || !this.ctx) return;
    const t = this.ctx.currentTime;
    this.master.gain.cancelScheduledValues(t);
    this.master.gain.setValueAtTime(Math.max(this.master.gain.value, 0.0001), t);
    this.master.gain.exponentialRampToValueAtTime(0.0001, t + seconds);
  }

  /** Undo a pending fade (timer cancelled). */
  restoreMaster() {
    if (!this.master || !this.ctx) return;
    const t = this.ctx.currentTime;
    this.master.gain.cancelScheduledValues(t);
    this.master.gain.setTargetAtTime(Math.max(this.masterVolume, 0.0001), t, RAMP);
  }

  // ---- noise sources -------------------------------------------------------

  private noiseBuffer(ctx: AudioContext, color: "white" | "pink" | "brown"): AudioBuffer {
    const cached = this.noiseBuffers.get(color);
    if (cached) return cached;
    const seconds = 4;
    const len = ctx.sampleRate * seconds;
    const buffer = ctx.createBuffer(2, len, ctx.sampleRate);
    for (let ch = 0; ch < 2; ch++) {
      const data = buffer.getChannelData(ch);
      if (color === "white") {
        for (let i = 0; i < len; i++) data[i] = Math.random() * 2 - 1;
      } else if (color === "pink") {
        // Paul Kellet's economy pink-noise filter
        let b0 = 0, b1 = 0, b2 = 0;
        for (let i = 0; i < len; i++) {
          const w = Math.random() * 2 - 1;
          b0 = 0.99765 * b0 + w * 0.099046;
          b1 = 0.963 * b1 + w * 0.2965164;
          b2 = 0.57 * b2 + w * 1.0526913;
          data[i] = (b0 + b1 + b2 + w * 0.1848) * 0.18;
        }
      } else {
        // brown: leaky integrator over white noise
        let last = 0;
        for (let i = 0; i < len; i++) {
          const w = Math.random() * 2 - 1;
          last = (last + 0.02 * w) / 1.02;
          data[i] = last * 3.5;
        }
      }
    }
    this.noiseBuffers.set(color, buffer);
    return buffer;
  }

  private noiseSource(ctx: AudioContext, color: "white" | "pink" | "brown"): AudioBufferSourceNode {
    const src = ctx.createBufferSource();
    src.buffer = this.noiseBuffer(ctx, color);
    src.loop = true;
    src.start();
    return src;
  }

  private static lfo(ctx: AudioContext, frequency: number, depth: number, target: AudioParam): OscillatorNode {
    const osc = ctx.createOscillator();
    osc.frequency.value = frequency;
    const amp = ctx.createGain();
    amp.gain.value = depth;
    osc.connect(amp);
    amp.connect(target);
    osc.start();
    return osc;
  }

  // ---- sound builders ------------------------------------------------------

  private build(id: string, ctx: AudioContext, out: GainNode): Cleanup {
    switch (id) {
      case "white": return this.buildNoise(ctx, out, "white", 0.5);
      case "pink": return this.buildNoise(ctx, out, "pink", 0.9);
      case "brown": return this.buildNoise(ctx, out, "brown", 0.9);
      case "rain": return this.buildRain(ctx, out);
      case "thunder": return this.buildThunder(ctx, out);
      case "ocean": return this.buildOcean(ctx, out);
      case "stream": return this.buildStream(ctx, out);
      case "wind": return this.buildWind(ctx, out);
      case "birds": return this.buildBirds(ctx, out);
      case "crickets": return this.buildCrickets(ctx, out);
      case "fire": return this.buildFire(ctx, out);
      case "fan": return this.buildFan(ctx, out);
      case "train": return this.buildTrain(ctx, out);
      case "heartbeat": return this.buildHeartbeat(ctx, out);
      case "delta": return this.buildBinaural(ctx, out, 133, 2.5);
      case "theta": return this.buildBinaural(ctx, out, 144, 6);
      case "alpha": return this.buildBinaural(ctx, out, 160, 10);
      case "piano": return this.buildDreamPiano(ctx, out);
      case "musicbox": return this.buildMusicBox(ctx, out);
      case "bowl": return this.buildSingingBowl(ctx, out);
      default: return this.buildNoise(ctx, out, "pink", 0.6);
    }
  }

  private buildNoise(ctx: AudioContext, out: GainNode, color: "white" | "pink" | "brown", level: number): Cleanup {
    const src = this.noiseSource(ctx, color);
    const g = ctx.createGain();
    g.gain.value = level;
    src.connect(g);
    g.connect(out);
    return () => { src.stop(); src.disconnect(); g.disconnect(); };
  }

  private buildRain(ctx: AudioContext, out: GainNode): Cleanup {
    // Body: dense wash of lowpassed white noise
    const body = this.noiseSource(ctx, "white");
    const bodyLp = ctx.createBiquadFilter();
    bodyLp.type = "lowpass";
    bodyLp.frequency.value = 1500;
    const bodyGain = ctx.createGain();
    bodyGain.gain.value = 0.4;
    body.connect(bodyLp); bodyLp.connect(bodyGain); bodyGain.connect(out);

    // Patter: high shimmer with a slow random flutter
    const patter = this.noiseSource(ctx, "white");
    const patterBp = ctx.createBiquadFilter();
    patterBp.type = "bandpass";
    patterBp.frequency.value = 4800;
    patterBp.Q.value = 0.6;
    const patterGain = ctx.createGain();
    patterGain.gain.value = 0.12;
    const flutter = AudioEngine.lfo(ctx, 0.4, 0.05, patterGain.gain);
    patter.connect(patterBp); patterBp.connect(patterGain); patterGain.connect(out);

    // Occasional close droplets
    let alive = true;
    const drop = () => {
      if (!alive) return;
      const t = ctx.currentTime;
      const osc = ctx.createOscillator();
      osc.type = "sine";
      const f = 900 + Math.random() * 1800;
      osc.frequency.setValueAtTime(f, t);
      osc.frequency.exponentialRampToValueAtTime(f * 0.55, t + 0.08);
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(0.02 + Math.random() * 0.03, t + 0.005);
      g.gain.exponentialRampToValueAtTime(0.0001, t + 0.09);
      osc.connect(g); g.connect(out);
      osc.start(t); osc.stop(t + 0.12);
      timers.push(window.setTimeout(drop, 250 + Math.random() * 900));
    };
    const timers: number[] = [window.setTimeout(drop, 400)];

    return () => {
      alive = false;
      timers.forEach(clearTimeout);
      body.stop(); patter.stop(); flutter.stop();
      [body, bodyLp, bodyGain, patter, patterBp, patterGain].forEach((n) => n.disconnect());
    };
  }

  private buildThunder(ctx: AudioContext, out: GainNode): Cleanup {
    let alive = true;
    const timers: number[] = [];
    const rumble = () => {
      if (!alive) return;
      const t = ctx.currentTime;
      const src = this.noiseSource(ctx, "brown");
      const lp = ctx.createBiquadFilter();
      lp.type = "lowpass";
      lp.frequency.setValueAtTime(140, t);
      lp.frequency.exponentialRampToValueAtTime(50, t + 3);
      const g = ctx.createGain();
      const peak = 0.5 + Math.random() * 0.5;
      const decay = 3 + Math.random() * 4;
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(peak, t + 0.25 + Math.random() * 0.4);
      g.gain.exponentialRampToValueAtTime(0.0001, t + decay);
      src.connect(lp); lp.connect(g); g.connect(out);
      timers.push(window.setTimeout(() => { src.stop(); src.disconnect(); lp.disconnect(); g.disconnect(); }, (decay + 0.5) * 1000));
      timers.push(window.setTimeout(rumble, 8000 + Math.random() * 16000));
    };
    timers.push(window.setTimeout(rumble, 1500));
    return () => { alive = false; timers.forEach(clearTimeout); };
  }

  private buildOcean(ctx: AudioContext, out: GainNode): Cleanup {
    const swell = this.noiseSource(ctx, "brown");
    const lp = ctx.createBiquadFilter();
    lp.type = "lowpass";
    lp.frequency.value = 900;
    const swellGain = ctx.createGain();
    swellGain.gain.value = 0.55;
    const filterLfo = AudioEngine.lfo(ctx, 0.065, 550, lp.frequency);
    const gainLfo = AudioEngine.lfo(ctx, 0.065, 0.3, swellGain.gain);
    swell.connect(lp); lp.connect(swellGain); swellGain.connect(out);

    // Foam hiss riding the crest of each wave
    const hiss = this.noiseSource(ctx, "white");
    const hp = ctx.createBiquadFilter();
    hp.type = "highpass";
    hp.frequency.value = 1800;
    const hissGain = ctx.createGain();
    hissGain.gain.value = 0.05;
    const hissLfo = AudioEngine.lfo(ctx, 0.065, 0.045, hissGain.gain);
    hiss.connect(hp); hp.connect(hissGain); hissGain.connect(out);

    return () => {
      [swell, hiss, filterLfo, gainLfo, hissLfo].forEach((n) => n.stop());
      [swell, lp, swellGain, hiss, hp, hissGain].forEach((n) => n.disconnect());
    };
  }

  private buildStream(ctx: AudioContext, out: GainNode): Cleanup {
    const src = this.noiseSource(ctx, "white");
    const stops: OscillatorNode[] = [];
    const nodes: AudioNode[] = [src];
    [[1300, 1.2, 0.28, 0.31, 180], [2600, 1.0, 0.18, 0.47, 320]].forEach(
      ([freq, q, level, rate, depth]) => {
        const bp = ctx.createBiquadFilter();
        bp.type = "bandpass";
        bp.frequency.value = freq;
        bp.Q.value = q;
        const g = ctx.createGain();
        g.gain.value = level;
        stops.push(AudioEngine.lfo(ctx, rate, depth, bp.frequency));
        src.connect(bp); bp.connect(g); g.connect(out);
        nodes.push(bp, g);
      }
    );
    return () => {
      src.stop(); stops.forEach((o) => o.stop());
      nodes.forEach((n) => n.disconnect());
    };
  }

  private buildWind(ctx: AudioContext, out: GainNode): Cleanup {
    const src = this.noiseSource(ctx, "pink");
    const bp = ctx.createBiquadFilter();
    bp.type = "bandpass";
    bp.frequency.value = 550;
    bp.Q.value = 0.9;
    const g = ctx.createGain();
    g.gain.value = 0.6;
    const freqLfo = AudioEngine.lfo(ctx, 0.05, 280, bp.frequency);
    const gustLfo = AudioEngine.lfo(ctx, 0.11, 0.28, g.gain);
    src.connect(bp); bp.connect(g); g.connect(out);
    return () => {
      [src, freqLfo, gustLfo].forEach((n) => n.stop());
      [src, bp, g].forEach((n) => n.disconnect());
    };
  }

  private buildBirds(ctx: AudioContext, out: GainNode): Cleanup {
    let alive = true;
    const timers: number[] = [];
    const chirp = (t: number, base: number, pan: StereoPannerNode) => {
      const osc = ctx.createOscillator();
      osc.type = "sine";
      osc.frequency.setValueAtTime(base, t);
      osc.frequency.exponentialRampToValueAtTime(base * (1.2 + Math.random() * 0.6), t + 0.05);
      osc.frequency.exponentialRampToValueAtTime(base * 0.9, t + 0.1);
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(0.12, t + 0.015);
      g.gain.exponentialRampToValueAtTime(0.0001, t + 0.12);
      osc.connect(g); g.connect(pan);
      osc.start(t); osc.stop(t + 0.15);
    };
    const phrase = () => {
      if (!alive) return;
      const pan = ctx.createStereoPanner();
      pan.pan.value = Math.random() * 1.6 - 0.8;
      pan.connect(out);
      const base = 2200 + Math.random() * 2200;
      const n = 2 + Math.floor(Math.random() * 4);
      for (let i = 0; i < n; i++) {
        chirp(ctx.currentTime + i * (0.14 + Math.random() * 0.1), base * (1 + Math.random() * 0.15), pan);
      }
      timers.push(window.setTimeout(() => pan.disconnect(), 1500));
      timers.push(window.setTimeout(phrase, 1500 + Math.random() * 5500));
    };
    timers.push(window.setTimeout(phrase, 600));
    return () => { alive = false; timers.forEach(clearTimeout); };
  }

  private buildCrickets(ctx: AudioContext, out: GainNode): Cleanup {
    const cleanups: Cleanup[] = [];
    [[4300, -0.6, 26], [4650, 0.6, 31]].forEach(([freq, panPos, trem]) => {
      const osc = ctx.createOscillator();
      osc.type = "sine";
      osc.frequency.value = freq;
      const tremGain = ctx.createGain();
      tremGain.gain.value = 0;
      const tremLfo = AudioEngine.lfo(ctx, trem, 0.5, tremGain.gain);
      const burst = ctx.createGain();
      burst.gain.value = 0;
      const pan = ctx.createStereoPanner();
      pan.pan.value = panPos;
      osc.connect(tremGain); tremGain.connect(burst); burst.connect(pan); pan.connect(out);
      osc.start();
      let alive = true;
      const timers: number[] = [];
      const cycle = () => {
        if (!alive) return;
        const t = ctx.currentTime;
        const on = 0.35 + Math.random() * 0.5;
        burst.gain.setTargetAtTime(0.06, t, 0.02);
        burst.gain.setTargetAtTime(0, t + on, 0.03);
        timers.push(window.setTimeout(cycle, (on + 0.3 + Math.random() * 0.9) * 1000));
      };
      timers.push(window.setTimeout(cycle, Math.random() * 800));
      cleanups.push(() => {
        alive = false; timers.forEach(clearTimeout);
        osc.stop(); tremLfo.stop();
        [osc, tremGain, burst, pan].forEach((n) => n.disconnect());
      });
    });
    return () => cleanups.forEach((fn) => fn());
  }

  private buildFire(ctx: AudioContext, out: GainNode): Cleanup {
    // Low roar
    const roar = this.noiseSource(ctx, "brown");
    const lp = ctx.createBiquadFilter();
    lp.type = "lowpass";
    lp.frequency.value = 350;
    const roarGain = ctx.createGain();
    roarGain.gain.value = 0.35;
    const roarLfo = AudioEngine.lfo(ctx, 0.3, 0.1, roarGain.gain);
    roar.connect(lp); lp.connect(roarGain); roarGain.connect(out);

    // Crackles: tiny bright noise bursts at random density
    let alive = true;
    const timers: number[] = [];
    const crackle = () => {
      if (!alive) return;
      const t = ctx.currentTime;
      const src = this.noiseSource(ctx, "white");
      const hp = ctx.createBiquadFilter();
      hp.type = "highpass";
      hp.frequency.value = 1600 + Math.random() * 2500;
      const g = ctx.createGain();
      const dur = 0.008 + Math.random() * 0.04;
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(0.08 + Math.random() * 0.22, t + 0.003);
      g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
      src.connect(hp); hp.connect(g); g.connect(out);
      timers.push(window.setTimeout(() => { src.stop(); src.disconnect(); hp.disconnect(); g.disconnect(); }, dur * 1000 + 100));
      timers.push(window.setTimeout(crackle, 30 + Math.random() * 350));
    };
    timers.push(window.setTimeout(crackle, 100));

    return () => {
      alive = false; timers.forEach(clearTimeout);
      roar.stop(); roarLfo.stop();
      [roar, lp, roarGain].forEach((n) => n.disconnect());
    };
  }

  private buildFan(ctx: AudioContext, out: GainNode): Cleanup {
    const noise = this.noiseSource(ctx, "brown");
    const lp = ctx.createBiquadFilter();
    lp.type = "lowpass";
    lp.frequency.value = 450;
    const noiseGain = ctx.createGain();
    noiseGain.gain.value = 0.55;
    noise.connect(lp); lp.connect(noiseGain); noiseGain.connect(out);

    const hum = ctx.createOscillator();
    hum.type = "sawtooth";
    hum.frequency.value = 112;
    const humLp = ctx.createBiquadFilter();
    humLp.type = "lowpass";
    humLp.frequency.value = 260;
    const humGain = ctx.createGain();
    humGain.gain.value = 0.04;
    const wobble = AudioEngine.lfo(ctx, 3.7, 0.012, humGain.gain);
    hum.connect(humLp); humLp.connect(humGain); humGain.connect(out);
    hum.start();

    return () => {
      [noise, hum, wobble].forEach((n) => n.stop());
      [noise, lp, noiseGain, hum, humLp, humGain].forEach((n) => n.disconnect());
    };
  }

  private buildTrain(ctx: AudioContext, out: GainNode): Cleanup {
    const rumble = this.noiseSource(ctx, "brown");
    const lp = ctx.createBiquadFilter();
    lp.type = "lowpass";
    lp.frequency.value = 220;
    const rumbleGain = ctx.createGain();
    rumbleGain.gain.value = 0.5;
    const sway = AudioEngine.lfo(ctx, 0.9, 0.08, rumbleGain.gain);
    rumble.connect(lp); lp.connect(rumbleGain); rumbleGain.connect(out);

    let alive = true;
    const timers: number[] = [];
    const clack = (t: number, level: number) => {
      const src = this.noiseSource(ctx, "white");
      const bp = ctx.createBiquadFilter();
      bp.type = "bandpass";
      bp.frequency.value = 900;
      bp.Q.value = 1.4;
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(level, t + 0.005);
      g.gain.exponentialRampToValueAtTime(0.0001, t + 0.07);
      src.connect(bp); bp.connect(g); g.connect(out);
      timers.push(window.setTimeout(() => { src.stop(); src.disconnect(); bp.disconnect(); g.disconnect(); }, 200));
    };
    const cycle = () => {
      if (!alive) return;
      const t = ctx.currentTime;
      clack(t, 0.09); clack(t + 0.16, 0.07);
      clack(t + 0.75, 0.08); clack(t + 0.91, 0.06);
      timers.push(window.setTimeout(cycle, 1500));
    };
    timers.push(window.setTimeout(cycle, 200));

    return () => {
      alive = false; timers.forEach(clearTimeout);
      rumble.stop(); sway.stop();
      [rumble, lp, rumbleGain].forEach((n) => n.disconnect());
    };
  }

  private buildHeartbeat(ctx: AudioContext, out: GainNode): Cleanup {
    let alive = true;
    const timers: number[] = [];
    const thump = (t: number, level: number) => {
      const osc = ctx.createOscillator();
      osc.type = "sine";
      osc.frequency.setValueAtTime(72, t);
      osc.frequency.exponentialRampToValueAtTime(38, t + 0.14);
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(level, t + 0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, t + 0.22);
      osc.connect(g); g.connect(out);
      osc.start(t); osc.stop(t + 0.3);
    };
    const beat = () => {
      if (!alive) return;
      const t = ctx.currentTime;
      thump(t, 0.9);        // lub
      thump(t + 0.32, 0.55); // dub
      timers.push(window.setTimeout(beat, 1050));
    };
    timers.push(window.setTimeout(beat, 100));
    return () => { alive = false; timers.forEach(clearTimeout); };
  }

  private buildBinaural(ctx: AudioContext, out: GainNode, carrier: number, beat: number): Cleanup {
    const make = (freq: number, panPos: number) => {
      const osc = ctx.createOscillator();
      osc.type = "sine";
      osc.frequency.value = freq;
      const pan = ctx.createStereoPanner();
      pan.pan.value = panPos;
      const g = ctx.createGain();
      g.gain.value = 0.5;
      osc.connect(g); g.connect(pan); pan.connect(out);
      osc.start();
      return { osc, pan, g };
    };
    const left = make(carrier, -1);
    const right = make(carrier + beat, 1);
    return () => {
      left.osc.stop(); right.osc.stop();
      [left.osc, left.g, left.pan, right.osc, right.g, right.pan].forEach((n) => n.disconnect());
    };
  }

  /** Shared space for melodic sounds: feedback delay as a simple reverb. */
  private makeSpace(ctx: AudioContext, out: GainNode, delayTime: number, feedback: number) {
    const input = ctx.createGain();
    const delay = ctx.createDelay(2);
    delay.delayTime.value = delayTime;
    const fb = ctx.createGain();
    fb.gain.value = feedback;
    const damp = ctx.createBiquadFilter();
    damp.type = "lowpass";
    damp.frequency.value = 2400;
    input.connect(out);
    input.connect(delay);
    delay.connect(damp); damp.connect(fb); fb.connect(delay);
    delay.connect(out);
    const cleanup = () => [input, delay, fb, damp].forEach((n) => n.disconnect());
    return { input, cleanup };
  }

  private buildDreamPiano(ctx: AudioContext, out: GainNode): Cleanup {
    // A-minor pentatonic across two octaves; slow generative phrases
    const scale = [220, 261.63, 293.66, 329.63, 392, 440, 523.25, 587.33];
    const { input, cleanup: spaceCleanup } = this.makeSpace(ctx, out, 0.42, 0.38);
    let alive = true;
    const timers: number[] = [];
    let prev = 3;
    const note = () => {
      if (!alive) return;
      // random walk over the scale sounds intentional, not random
      prev = Math.min(scale.length - 1, Math.max(0, prev + Math.floor(Math.random() * 5) - 2));
      const f = scale[prev];
      const t = ctx.currentTime;
      const osc = ctx.createOscillator();
      osc.type = "triangle";
      osc.frequency.value = f;
      const harm = ctx.createOscillator();
      harm.type = "sine";
      harm.frequency.value = f * 2;
      const harmG = ctx.createGain();
      harmG.gain.value = 0.15;
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(0.22, t + 0.03);
      g.gain.exponentialRampToValueAtTime(0.0001, t + 3.2);
      osc.connect(g); harm.connect(harmG); harmG.connect(g); g.connect(input);
      osc.start(t); harm.start(t);
      osc.stop(t + 3.4); harm.stop(t + 3.4);
      timers.push(window.setTimeout(() => { g.disconnect(); harmG.disconnect(); }, 3600));
      timers.push(window.setTimeout(note, 1600 + Math.random() * 3200));
    };
    timers.push(window.setTimeout(note, 300));
    return () => { alive = false; timers.forEach(clearTimeout); spaceCleanup(); };
  }

  private buildMusicBox(ctx: AudioContext, out: GainNode): Cleanup {
    // C-major pentatonic, high register, gentle mechanical timing
    const scale = [523.25, 587.33, 659.25, 783.99, 880, 1046.5];
    const { input, cleanup: spaceCleanup } = this.makeSpace(ctx, out, 0.31, 0.3);
    let alive = true;
    const timers: number[] = [];
    let prev = 2;
    const note = () => {
      if (!alive) return;
      prev = Math.min(scale.length - 1, Math.max(0, prev + Math.floor(Math.random() * 3) - 1));
      const f = scale[prev];
      const t = ctx.currentTime;
      const osc = ctx.createOscillator();
      osc.type = "sine";
      osc.frequency.value = f;
      const shimmer = ctx.createOscillator();
      shimmer.type = "sine";
      shimmer.frequency.value = f * 3.01; // slightly inharmonic tine partial
      const shimmerG = ctx.createGain();
      shimmerG.gain.value = 0.12;
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.0001, t);
      g.gain.exponentialRampToValueAtTime(0.2, t + 0.008);
      g.gain.exponentialRampToValueAtTime(0.0001, t + 1.6);
      osc.connect(g); shimmer.connect(shimmerG); shimmerG.connect(g); g.connect(input);
      osc.start(t); shimmer.start(t);
      osc.stop(t + 1.8); shimmer.stop(t + 1.8);
      timers.push(window.setTimeout(() => { g.disconnect(); shimmerG.disconnect(); }, 2000));
      timers.push(window.setTimeout(note, 700 + Math.random() * 1100));
    };
    timers.push(window.setTimeout(note, 300));
    return () => { alive = false; timers.forEach(clearTimeout); spaceCleanup(); };
  }

  private buildSingingBowl(ctx: AudioContext, out: GainNode): Cleanup {
    let alive = true;
    const timers: number[] = [];
    const strike = () => {
      if (!alive) return;
      const t = ctx.currentTime;
      const base = 180 + Math.random() * 60;
      // real bowls ring with inharmonic partials
      [1, 2.72, 5.35].forEach((ratio, i) => {
        const osc = ctx.createOscillator();
        osc.type = "sine";
        osc.frequency.value = base * ratio;
        // slow beating between close partials
        const detune = ctx.createOscillator();
        detune.type = "sine";
        detune.frequency.value = 0.6 + i * 0.4;
        const detuneG = ctx.createGain();
        detuneG.gain.value = 1.2;
        detune.connect(detuneG); detuneG.connect(osc.frequency);
        const g = ctx.createGain();
        const level = [0.28, 0.12, 0.05][i];
        const decay = 9 - i * 2;
        g.gain.setValueAtTime(0.0001, t);
        g.gain.exponentialRampToValueAtTime(level, t + 0.04);
        g.gain.exponentialRampToValueAtTime(0.0001, t + decay);
        osc.connect(g); g.connect(out);
        osc.start(t); detune.start(t);
        osc.stop(t + decay + 0.2); detune.stop(t + decay + 0.2);
        timers.push(window.setTimeout(() => { g.disconnect(); detuneG.disconnect(); }, (decay + 0.5) * 1000));
      });
      timers.push(window.setTimeout(strike, 11000 + Math.random() * 9000));
    };
    timers.push(window.setTimeout(strike, 400));
    return () => { alive = false; timers.forEach(clearTimeout); };
  }
}

// Singleton — the engine must survive across screen/tab switches.
let engine: AudioEngine | null = null;
export function getEngine(): AudioEngine {
  if (!engine) engine = new AudioEngine();
  return engine;
}
