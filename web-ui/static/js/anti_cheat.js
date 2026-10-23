/**
 * ProctorGuard - Anti-Cheat Security & Sandbox Telemetry Engine
 * Enforces fullscreen lockdown, multi-monitor restrictions, screen capture verification,
 * tab switch / focus loss detection, keyboard & clipboard blocking, and violation frame grabber.
 */

class AntiCheat {
  /**
   * @param {Object} options
   * @param {string} options.candidateId
   * @param {string} options.candidateName
   * @param {HTMLVideoElement} [options.webcamVideoElement]
   * @param {HTMLVideoElement} [options.screenVideoElement]
   * @param {number} [options.maxWarnings=3]
   * @param {Function} [options.onViolation]
   * @param {Function} [options.onLockdown]
   * @param {Function} [options.onWarningUpdate]
   * @param {ProctorSocket} [options.socket]
   */
  constructor(options = {}) {
    this.candidateId = options.candidateId || 'CAND-USER';
    this.candidateName = options.candidateName || 'Candidate';
    this.sessionId = options.sessionId || 'default';
    this.webcamVideoElement = options.webcamVideoElement || null;
    this.screenVideoElement = options.screenVideoElement || null;
    this.maxWarnings = options.maxWarnings || 3;
    this.onViolation = options.onViolation || null;
    this.onLockdown = options.onLockdown || null;
    this.onWarningUpdate = options.onWarningUpdate || null;
    this.socket = options.socket || null;

    this.warningCount = 0;
    this.isLocked = false;
    this.isActive = false;
    this.screenStream = null;
    this.violationsHistory = [];

    // Cooldown map to avoid rapid duplicate triggers
    this.lastTriggerTimes = {};

    this._boundHandleFullscreenChange = this._handleFullscreenChange.bind(this);
    this._boundHandleVisibilityChange = this._handleVisibilityChange.bind(this);
    this._boundHandleWindowBlur = this._handleWindowBlur.bind(this);
    this._boundHandleWindowFocus = this._handleWindowFocus.bind(this);
    this._boundHandleKeydown = this._handleKeydown.bind(this);
    this._boundBlockEvent = this._blockEvent.bind(this);
    this._boundHandleScreenChange = this._handleScreenChange.bind(this);
  }

  /**
   * Starts all monitoring systems and security listeners.
   */
  start() {
    if (this.isActive) return;
    this.isActive = true;

    // 1. Fullscreen change listener
    document.addEventListener('fullscreenchange', this._boundHandleFullscreenChange);
    document.addEventListener('webkitfullscreenchange', this._boundHandleFullscreenChange);

    // 2. Tab switch and focus loss listeners
    document.addEventListener('visibilitychange', this._boundHandleVisibilityChange);
    window.addEventListener('blur', this._boundHandleWindowBlur);
    window.addEventListener('focus', this._boundHandleWindowFocus);

    // 3. Multi-monitor checks
    this._setupMultiMonitorDetection();

    // 4. Keyboard shortcuts & devtools blocking
    window.addEventListener('keydown', this._boundHandleKeydown, true);

    // 5. Context menu and clipboard blocking
    document.addEventListener('contextmenu', this._boundBlockEvent, true);
    document.addEventListener('copy', this._boundBlockEvent, true);
    document.addEventListener('cut', this._boundBlockEvent, true);
    document.addEventListener('paste', this._boundBlockEvent, true);

    console.log('AntiCheat: All telemetry guards active for candidate:', this.candidateId);
  }

  /**
   * Enforces full-screen display.
   */
  async requestFullscreen() {
    try {
      const elem = document.documentElement || document.body;
      if (elem.requestFullscreen) {
        await elem.requestFullscreen();
      } else if (elem.webkitRequestFullscreen) {
        await elem.webkitRequestFullscreen();
      } else if (elem.mozRequestFullScreen) {
        await elem.mozRequestFullScreen();
      } else if (elem.msRequestFullscreen) {
        await elem.msRequestFullscreen();
      }
      return true;
    } catch (err) {
      console.warn('AntiCheat: Fullscreen request failed or was denied:', err);
      return false;
    }
  }

  /**
   * Requests entire screen display capture with integrity check.
   */
  async startScreenCapture() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) {
      throw new Error('Screen capture is not supported in this browser environment.');
    }

    try {
      const stream = await navigator.mediaDevices.getDisplayMedia({
        video: {
          displaySurface: 'monitor', // Requests entire screen
          cursor: 'always'
        },
        audio: false
      });

      this.screenStream = stream;
      const videoTrack = stream.getVideoTracks()[0];
      const settings = (videoTrack && videoTrack.getSettings) ? videoTrack.getSettings() : {};

      // Verify that entire monitor was captured if supported
      if (settings.displaySurface && settings.displaySurface !== 'monitor') {
        stream.getTracks().forEach(t => t.stop());
        this.triggerViolation({
          type: 'DISPLAY_TOPOLOGY_CHANGED',
          severity: 'CRITICAL',
          message: `Forbidden display surface '${settings.displaySurface}' selected. Entire Screen capture is strictly required.`,
          details: { violationSubtype: 'NON_FULLSCREEN_DISPLAY_CAPTURE', surface: settings.displaySurface }
        });
        throw new Error(`Policy violation: Selected '${settings.displaySurface}' display capture. Candidate must share Entire Screen.`);
      }

      // Detect if user clicks "Stop sharing" in browser banner
      videoTrack.onended = () => {
        this.triggerViolation({
          type: 'DISPLAY_TOPOLOGY_CHANGED',
          severity: 'CRITICAL',
          message: 'Screen capture stream was stopped by candidate.',
          details: { violationSubtype: 'SCREEN_CAPTURE_TERMINATED' }
        });
      };

      if (this.screenVideoElement) {
        this.screenVideoElement.srcObject = stream;
        this.screenVideoElement.play().catch(e => console.warn(e));
      }

      return stream;
    } catch (err) {
      console.error('AntiCheat: Failed to obtain screen capture stream:', err);
      throw err;
    }
  }

  /**
   * Multi-monitor detection using Screen Details API and resolution heuristics.
   */
  _setupMultiMonitorDetection() {
    // 1. Screen Details API check
    if (window.screen && 'isExtended' in window.screen) {
      if (window.screen.isExtended) {
        this.triggerViolation({
          type: 'MULTIPLE_DISPLAYS_DETECTED',
          severity: 'HIGH',
          message: 'Multiple monitors detected. Secondary screens must be disconnected.'
        });
      }

      // Listen for display connect/disconnect safely
      if (typeof window.screen.addEventListener === 'function') {
        window.screen.addEventListener('change', this._boundHandleScreenChange);
      }
    }

    // 2. Fallback heuristic: check window screen availability
    this.screenCheckInterval = setInterval(() => {
      if (window.screen && window.screen.isExtended) {
        this.triggerViolation({
          type: 'MULTIPLE_DISPLAYS_DETECTED',
          severity: 'HIGH',
          message: 'Multiple monitors detected. Disconnect external displays.'
        });
      }
    }, 4000);
  }

  _handleScreenChange() {
    if (window.screen && window.screen.isExtended) {
      this.triggerViolation({
        type: 'MULTIPLE_DISPLAYS_DETECTED',
        severity: 'HIGH',
        message: 'Secondary monitor connected during active exam session.'
      });
    }
  }

  /**
   * Fullscreen exit detector.
   */
  _handleFullscreenChange() {
    const isFullscreen = !!(document.fullscreenElement || document.webkitFullscreenElement);
    if (!isFullscreen && this.isActive && !this.isLocked) {
      this.triggerViolation({
        type: 'FULLSCREEN_EXIT',
        severity: 'HIGH',
        message: 'Candidate exited required fullscreen exam lockdown.'
      });
    }
  }

  /**
   * Tab switch / window minimization detector.
   */
  _handleVisibilityChange() {
    if (document.hidden && this.isActive && !this.isLocked) {
      this.triggerViolation({
        type: 'TAB_BLUR',
        severity: 'HIGH',
        message: 'Candidate switched tabs or minimized exam window.'
      });
    }
  }

  /**
   * Focus loss detector (clicks outside browser window).
   */
  _handleWindowBlur() {
    if (this.isActive && !this.isLocked) {
      this.triggerViolation({
        type: 'TAB_BLUR',
        severity: 'HIGH',
        message: 'Exam window lost focus (user clicked on external app or window).'
      });
    }
  }

  _handleWindowFocus() {
    // Return to focus logged
    console.log('AntiCheat: Window regained focus.');
  }

  /**
   * Keyboard shortcuts & Developer tools blocker.
   */
  _handleKeydown(e) {
    if (!this.isActive) return;

    // F12 developer tools
    if (e.key === 'F12' || e.keyCode === 123) {
      e.preventDefault();
      e.stopPropagation();
      this.triggerViolation({
        type: 'DEVTOOLS_ATTEMPT',
        severity: 'CRITICAL',
        message: 'F12 Developer Tools shortcut blocked.'
      });
      return false;
    }

    // Ctrl+Shift+I / Ctrl+Shift+J / Ctrl+Shift+C / Ctrl+U
    if (e.ctrlKey && (e.key === 'I' || e.key === 'J' || e.key === 'C' || e.key === 'u' || e.key === 'U') && (e.shiftKey || e.key === 'u' || e.key === 'U')) {
      e.preventDefault();
      e.stopPropagation();
      this.triggerViolation({
        type: 'DEVTOOLS_ATTEMPT',
        severity: 'CRITICAL',
        message: 'DevTools inspection shortcut blocked.'
      });
      return false;
    }

    // Alt+Tab
    if (e.altKey && (e.key === 'Tab' || e.keyCode === 9)) {
      e.preventDefault();
      e.stopPropagation();
      this.triggerViolation({
        type: 'TAB_BLUR',
        severity: 'HIGH',
        message: 'Alt+Tab application switch attempt blocked.'
      });
      return false;
    }

    // Alt+F4
    if (e.altKey && e.key === 'F4') {
      e.preventDefault();
      e.stopPropagation();
      return false;
    }

    // Ctrl+C, Ctrl+V, Ctrl+X
    if (e.ctrlKey && ['c', 'v', 'x', 'a', 'p', 's'].includes(e.key.toLowerCase())) {
      // If pressing Ctrl+C or Ctrl+V in exam, prevent unless specifically allowed
      e.preventDefault();
      e.stopPropagation();
      this.triggerViolation({
        type: 'CLIPBOARD_VIOLATION',
        severity: 'LOW',
        message: `Blocked shortcut Ctrl+${e.key.toUpperCase()}. Clipboard access is prohibited.`
      });
      return false;
    }

    // Windows / Meta key
    if (e.key === 'Meta' || e.keyCode === 91) {
      e.preventDefault();
      e.stopPropagation();
      this.triggerViolation({
        type: 'TAB_BLUR',
        severity: 'HIGH',
        message: 'System Meta/Windows key press blocked.'
      });
      return false;
    }
  }

  /**
   * Block right click context menu and clipboard actions.
   */
  _blockEvent(e) {
    if (!this.isActive) return;
    e.preventDefault();
    e.stopPropagation();

    let violationType = 'CONTEXT_MENU_ATTEMPT';
    let message = 'Right-click context menu is disabled.';
    if (e.type === 'copy' || e.type === 'cut' || e.type === 'paste') {
      violationType = 'CLIPBOARD_VIOLATION';
      message = `Prohibited ${e.type} action prevented.`;
    }

    this.triggerViolation({
      type: violationType,
      severity: 'LOW',
      message: message
    });

    return false;
  }

  /**
   * Capture a lightweight JPEG frame thumbnail from a video element.
   * @param {HTMLVideoElement} videoElem
   * @param {number} [width=320]
   * @param {number} [height=240]
   * @returns {string|null} base64 data URI
   */
  captureSnapshot(videoElem, width = 320, height = 240) {
    if (!videoElem || videoElem.readyState < 2) {
      return null;
    }

    try {
      const canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(videoElem, 0, 0, width, height);
      return canvas.toDataURL('image/jpeg', 0.65);
    } catch (err) {
      console.warn('AntiCheat: Failed to capture snapshot:', err);
      return null;
    }
  }

  /**
   * Records and handles a violation incident.
   * Automatically captures webcam and screen snapshots, increments warnings,
   * notifies proctor socket, and enforces lockdown upon exceeding max warnings.
   */
  triggerViolation({ type, severity = 'MEDIUM', message = '' }) {
    const now = Date.now();
    // 1. Throttle identical violation types within 2.5 seconds
    if (this.lastTriggerTimes[type] && (now - this.lastTriggerTimes[type] < 2500)) {
      return;
    }
    this.lastTriggerTimes[type] = now;

    // 2. Capture snapshots
    const cameraSnapshot = this.captureSnapshot(this.webcamVideoElement);
    const screenSnapshot = this.captureSnapshot(this.screenVideoElement);

    // 3. Increment warnings
    this.warningCount++;

    const incident = {
      id: 'INC-' + Math.random().toString(36).substring(2, 9).toUpperCase(),
      candidateId: this.candidateId,
      candidateName: this.candidateName,
      type: type,
      severity: severity,
      message: message,
      warningCount: this.warningCount,
      maxWarnings: this.maxWarnings,
      cameraSnapshot: cameraSnapshot,
      screenSnapshot: screenSnapshot,
      timestamp: new Date().toISOString()
    };

    this.violationsHistory.push(incident);

    console.warn(`[VIOLATION] [${severity}] ${type}: ${message} (Warning ${this.warningCount}/${this.maxWarnings})`);

    // 4. Update UI warning count
    if (this.onWarningUpdate) {
      this.onWarningUpdate(this.warningCount, this.maxWarnings, incident);
    }

    // 5. Notify violation listener
    if (this.onViolation) {
      this.onViolation(incident);
    }

    // 6. Broadcast to proctor via WebSocket
    if (this.socket) {
      if (typeof this.socket.sendIncident === 'function') {
        this.socket.sendIncident({
          sessionId: this.sessionId,
          candidateId: this.candidateId,
          timestamp: incident.timestamp,
          severity: severity,
          eventType: type,
          metadata: { message: message, warningCount: this.warningCount },
          snapshotFrame: cameraSnapshot
        });
      } else {
        this.socket.send({
          type: 'INCIDENT_ALERT',
          incident: incident
        });
      }
    }

    // 7. Check if exam should be locked
    if (this.warningCount >= this.maxWarnings && !this.isLocked) {
      this.lockExam(`Maximum allowed warnings (${this.maxWarnings}) exceeded. Exam session locked by automated proctor.`);
    }
  }

  /**
   * Lock candidate's exam screen.
   */
  lockExam(reason = 'Exam locked due to security policy violations.') {
    this.isLocked = true;
    console.error('AntiCheat: EXAM LOCKED.', reason);

    if (this.onLockdown) {
      this.onLockdown(reason);
    }

    if (this.socket) {
      this.socket.send({
        type: 'CANDIDATE_LOCKED',
        reason: reason
      });
    }
  }

  /**
   * Unlock candidate's exam screen (proctor remote action).
   */
  unlockExam() {
    this.isLocked = false;
    this.warningCount = Math.max(0, this.warningCount - 1);
    if (this.onWarningUpdate) {
      this.onWarningUpdate(this.warningCount, this.maxWarnings);
    }
  }

  /**
   * Reset flags & warnings.
   */
  clearFlags() {
    this.warningCount = 0;
    this.isLocked = false;
    if (this.onWarningUpdate) {
      this.onWarningUpdate(0, this.maxWarnings);
    }
  }

  /**
   * Clean up all event listeners.
   */
  destroy() {
    this.isActive = false;
    document.removeEventListener('fullscreenchange', this._boundHandleFullscreenChange);
    document.removeEventListener('webkitfullscreenchange', this._boundHandleFullscreenChange);
    document.removeEventListener('visibilitychange', this._boundHandleVisibilityChange);
    window.removeEventListener('blur', this._boundHandleWindowBlur);
    window.removeEventListener('focus', this._boundHandleWindowFocus);
    window.removeEventListener('keydown', this._boundHandleKeydown, true);
    document.removeEventListener('contextmenu', this._boundBlockEvent, true);
    document.removeEventListener('copy', this._boundBlockEvent, true);
    document.removeEventListener('cut', this._boundBlockEvent, true);
    document.removeEventListener('paste', this._boundBlockEvent, true);

    if (window.screen && window.screen.removeEventListener) {
      window.screen.removeEventListener('change', this._boundHandleScreenChange);
    }
    if (this.screenCheckInterval) clearInterval(this.screenCheckInterval);
    if (this.screenStream) {
      this.screenStream.getTracks().forEach(t => t.stop());
    }
  }
}

if (typeof window !== 'undefined') {
  window.AntiCheat = AntiCheat;
}
