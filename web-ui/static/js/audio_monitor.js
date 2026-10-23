/**
 * ProctorGuard - Audio Telemetry & Whisper/Voice Detection Engine
 * Uses Web Audio API (AudioContext, AnalyserNode) to compute real-time RMS,
 * drive live VU meters, and detect sustained whisper/voice events.
 */

class AudioMonitor {
  /**
   * @param {Object} options Configuration options
   * @param {number} [options.threshold=30] Volume threshold (0-100) considered active voice/whisper
   * @param {number} [options.sustainedDurationMs=1500] Minimum sustained duration in ms before firing incident
   * @param {number} [options.cooldownMs=4000] Throttle interval between alerts to prevent spamming
   * @param {HTMLElement|string} [options.vuBarElement] DOM element or selector for VU meter bar width
   * @param {HTMLElement|string} [options.vuLabelElement] DOM element or selector for volume text display
   * @param {Function} [options.onSuspiciousAudio] Callback for suspicious audio events
   * @param {Function} [options.onLevelUpdate] Callback for real-time volume updates
   */
  constructor(options = {}) {
    this.threshold = options.threshold ?? 30;
    this.sustainedDurationMs = options.sustainedDurationMs ?? 1500;
    this.cooldownMs = options.cooldownMs ?? 4000;
    this.vuBarElement = typeof options.vuBarElement === 'string'
      ? document.querySelector(options.vuBarElement)
      : options.vuBarElement;
    this.vuLabelElement = typeof options.vuLabelElement === 'string'
      ? document.querySelector(options.vuLabelElement)
      : options.vuLabelElement;

    this.onSuspiciousAudio = options.onSuspiciousAudio || null;
    this.onLevelUpdate = options.onLevelUpdate || null;

    this.audioContext = null;
    this.analyser = null;
    this.mediaStreamSource = null;
    this.animationFrameId = null;
    this.isRunning = false;

    // Sustained audio tracking state
    this.highVolumeStartTime = null;
    this.highVolumeFrameCount = 0;
    this.lastAlertTime = 0;
    this.currentLevel = 0;

    this._loop = this._loop.bind(this);
  }

  /**
   * Start analyzing the audio track from a MediaStream.
   * @param {MediaStream} stream
   */
  async start(stream) {
    if (!stream || !stream.getAudioTracks().length) {
      throw new Error('AudioMonitor: MediaStream has no audio tracks.');
    }

    // Stop any existing instance
    this.stop();

    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      this.audioContext = new AudioCtx();

      if (this.audioContext.state === 'suspended') {
        this.audioContext.resume().catch(e => console.warn('AudioContext resume deferred until user gesture:', e));
      }

      this.analyser = this.audioContext.createAnalyser();
      this.analyser.fftSize = 512;
      this.analyser.smoothingTimeConstant = 0.35;

      this.mediaStreamSource = this.audioContext.createMediaStreamSource(stream);
      this.mediaStreamSource.connect(this.analyser);

      this.isRunning = true;
      this.highVolumeStartTime = null;
      this.highVolumeFrameCount = 0;

      this._loop();
      console.log('AudioMonitor: Initialized and actively monitoring microphone telemetry.');
    } catch (err) {
      console.error('AudioMonitor: Failed to start audio monitor.', err);
      throw err;
    }
  }

  /**
   * Internal processing loop for RMS energy and frequency calculation.
   */
  _loop() {
    if (!this.isRunning || !this.analyser) return;

    const dataArray = new Uint8Array(this.analyser.frequencyBinCount);
    this.analyser.getByteTimeDomainData(dataArray);

    // Compute Root Mean Square (RMS) energy
    let sumSquares = 0;
    const len = dataArray.length;
    for (let i = 0; i < len; i++) {
      const normalizedSample = (dataArray[i] - 128) / 128;
      sumSquares += normalizedSample * normalizedSample;
    }
    const rms = Math.sqrt(sumSquares / len);

    // Scale RMS into an intuitive 0-100 volume rating
    // Typical speech ranges around rms 0.05 to 0.25
    let volume = Math.min(100, Math.round(rms * 280));
    this.currentLevel = volume;

    // Update Visual VU Meter in DOM if available
    this._updateVuMeter(volume);

    // Notify real-time listeners
    if (this.onLevelUpdate) {
      this.onLevelUpdate(volume, rms);
    }

    // Whisper & Voice Detection Analysis
    const now = Date.now();
    if (volume >= this.threshold) {
      this.highVolumeFrameCount++;
      if (!this.highVolumeStartTime) {
        this.highVolumeStartTime = now;
      }

      const sustainedDuration = now - this.highVolumeStartTime;
      const canAlert = (now - this.lastAlertTime) >= this.cooldownMs;

      // Check if volume sustained over 3 frames AND >= 1.5 seconds (or either threshold met)
      if ((sustainedDuration >= this.sustainedDurationMs || this.highVolumeFrameCount >= 45) && canAlert) {
        this._emitSuspiciousAudioEvent(volume, sustainedDuration);
        this.lastAlertTime = now;
        // Reset tracking counter so subsequent alerts measure fresh duration
        this.highVolumeStartTime = now;
        this.highVolumeFrameCount = 0;
      }
    } else {
      // Allow slight noise dips (grace window of 300ms) before full reset
      if (this.highVolumeStartTime && (now - this.highVolumeStartTime > 400)) {
        this.highVolumeStartTime = null;
        this.highVolumeFrameCount = 0;
      }
    }

    this.animationFrameId = requestAnimationFrame(this._loop);
  }

  /**
   * Updates the visual VU meter UI element.
   * @param {number} volume 0 - 100 scale
   */
  _updateVuMeter(volume) {
    if (this.vuBarElement) {
      this.vuBarElement.style.width = `${volume}%`;

      // Color coding based on energy levels
      if (volume > 70) {
        this.vuBarElement.style.background = '#ef4444'; // Red
      } else if (volume > 35) {
        this.vuBarElement.style.background = '#f59e0b'; // Amber / Yellow
      } else {
        this.vuBarElement.style.background = 'linear-gradient(90deg, #10b981, #34d399)'; // Emerald
      }
    }

    if (this.vuLabelElement) {
      this.vuLabelElement.textContent = `${volume}%`;
    }
  }

  /**
   * Dispatches the SUSPICIOUS_AUDIO_LEVEL event.
   */
  _emitSuspiciousAudioEvent(volume, durationMs) {
    const severity = volume > 65 ? 'HIGH' : 'MEDIUM';
    const incidentData = {
      type: 'SUSPICIOUS_AUDIO_LEVEL',
      severity: severity,
      volume: volume,
      durationMs: durationMs,
      timestamp: new Date().toISOString(),
      message: `Suspicious audio detected (volume: ${volume}%, sustained ${Math.round(durationMs / 1000 * 10) / 10}s)`
    };

    console.warn('AudioMonitor: SUSPICIOUS_AUDIO_LEVEL detected:', incidentData);

    // Dispatch global DOM event for system hooks
    window.dispatchEvent(new CustomEvent('SUSPICIOUS_AUDIO_LEVEL', { detail: incidentData }));

    // Invoke instance callback if configured
    if (typeof this.onSuspiciousAudio === 'function') {
      this.onSuspiciousAudio(incidentData);
    }
  }

  /**
   * Stop monitoring and release hardware audio context resources.
   */
  stop() {
    this.isRunning = false;
    if (this.animationFrameId) {
      cancelAnimationFrame(this.animationFrameId);
      this.animationFrameId = null;
    }

    if (this.mediaStreamSource) {
      this.mediaStreamSource.disconnect();
      this.mediaStreamSource = null;
    }

    if (this.audioContext && this.audioContext.state !== 'closed') {
      try {
        this.audioContext.close();
      } catch (e) {
        console.warn('AudioMonitor: Error closing AudioContext', e);
      }
      this.audioContext = null;
    }

    if (this.vuBarElement) {
      this.vuBarElement.style.width = '0%';
    }
    if (this.vuLabelElement) {
      this.vuLabelElement.textContent = '0%';
    }

    this.highVolumeStartTime = null;
    this.highVolumeFrameCount = 0;
  }

  /**
   * Safely resume AudioContext following a user interaction gesture.
   */
  async resumeContext() {
    if (this.audioContext && this.audioContext.state === 'suspended') {
      try {
        await this.audioContext.resume();
        console.log('AudioMonitor: AudioContext resumed cleanly after user interaction.');
      } catch (e) {
        console.warn('AudioMonitor: Failed to resume AudioContext:', e);
      }
    }
  }
}

// Attach to window for global browser usage
if (typeof window !== 'undefined') {
  window.AudioMonitor = AudioMonitor;
}
