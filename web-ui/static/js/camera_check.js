/**
 * ProctorGuard - Virtual Camera Detection & Hardware Integrity Checker
 * Inspects device labels via navigator.mediaDevices.enumerateDevices()
 * Flags and blocks streams originating from virtual camera software (OBS, ManyCam, etc.)
 */

class VirtualCameraError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'VirtualCameraError';
    this.code = 'VIRTUAL_CAMERA_DETECTED';
    this.details = details;
  }
}

class CameraChecker {
  // Common virtual camera software signatures
  static VIRTUAL_CAMERA_KEYWORDS = [
    'OBS',
    'Virtual',
    'v4l2loopback',
    'ManyCam',
    'SplitCam',
    'Fake',
    'DroidCam',
    'EpocCam',
    'Iriun',
    'CamTwist',
    'XSplit',
    'Snap Camera'
  ];

  /**
   * Inspects a device label string for virtual camera signatures.
   * @param {string} label
   * @returns {{ isVirtual: boolean, keyword: string|null }}
   */
  static isVirtualLabel(label) {
    if (!label || typeof label !== 'string') {
      return { isVirtual: false, keyword: null };
    }

    const lowerLabel = label.toLowerCase();
    for (const kw of CameraChecker.VIRTUAL_CAMERA_KEYWORDS) {
      if (lowerLabel.includes(kw.toLowerCase())) {
        return { isVirtual: true, keyword: kw };
      }
    }
    return { isVirtual: false, keyword: null };
  }

  /**
   * Enumerate all connected video input devices and analyze them.
   * @returns {Promise<{ clean: boolean, virtualDevices: MediaDeviceInfo[], validDevices: MediaDeviceInfo[], allDevices: MediaDeviceInfo[] }>}
   */
  static async scanDevices() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) {
      console.warn('CameraChecker: MediaDevices API not supported in this browser.');
      return { clean: true, virtualDevices: [], validDevices: [], allDevices: [] };
    }

    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      const videoDevices = devices.filter(d => d.kind === 'videoinput');
      const virtualDevices = [];
      const validDevices = [];

      videoDevices.forEach(device => {
        const { isVirtual, keyword } = CameraChecker.isVirtualLabel(device.label);
        if (isVirtual) {
          virtualDevices.push({
            deviceId: device.deviceId,
            label: device.label || 'Unknown Virtual Camera',
            keyword: keyword
          });
        } else {
          validDevices.push({
            deviceId: device.deviceId,
            label: device.label || 'Standard Hardware Camera'
          });
        }
      });

      const clean = virtualDevices.length === 0;

      return {
        clean,
        virtualDevices,
        validDevices,
        allDevices: videoDevices
      };
    } catch (err) {
      console.error('CameraChecker: Error enumerating media devices', err);
      throw err;
    }
  }

  /**
   * Requests camera stream with mandatory virtual camera heuristics verification.
   * Immediately terminates stream if a virtual camera is detected.
   * @param {MediaStreamConstraints} [constraints]
   * @returns {Promise<MediaStream>}
   */
  static async requestVerifiedStream(constraints = { video: { width: { ideal: 1280 }, height: { ideal: 720 } }, audio: true }) {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      throw new Error('MediaDevices.getUserMedia is not supported by your browser.');
    }

    // Step 1: Request media permissions to reveal hardware labels
    const stream = await navigator.mediaDevices.getUserMedia(constraints);

    // Step 2: Inspect active video tracks
    const videoTracks = stream.getVideoTracks();
    for (const track of videoTracks) {
      const trackLabel = track.label || '';
      const { isVirtual, keyword } = CameraChecker.isVirtualLabel(trackLabel);

      if (isVirtual) {
        // Kill the stream immediately to protect exam integrity
        stream.getTracks().forEach(t => t.stop());

        const errorDetails = {
          flaggedLabel: trackLabel,
          matchedKeyword: keyword,
          trackId: track.id,
          timestamp: new Date().toISOString()
        };

        // Emit security event
        window.dispatchEvent(new CustomEvent('VIRTUAL_CAMERA_DETECTED', {
          detail: errorDetails
        }));

        throw new VirtualCameraError(
          `Access Denied: Virtual camera device detected ("${trackLabel}"). You must use a physical hardware webcam.`,
          errorDetails
        );
      }
    }

    // Step 3: Run comprehensive scan across all device labels
    const scan = await CameraChecker.scanDevices();
    if (!scan.clean) {
      console.warn('CameraChecker: System has virtual cameras installed:', scan.virtualDevices);
      // We don't necessarily block if an unselected camera is virtual,
      // as long as the currently active track is genuine hardware.
    }

    console.log('CameraChecker: Hardware camera verification passed successfully.');
    return stream;
  }
}

// Attach globally
if (typeof window !== 'undefined') {
  window.CameraChecker = CameraChecker;
  window.VirtualCameraError = VirtualCameraError;
}
