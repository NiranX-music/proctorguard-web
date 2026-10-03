/**
 * ProctorGuard - Real-time WebSocket Protocol & Mesh Sync Bridge
 * Connects Candidate and Proctor Admin consoles via WebSocket,
 * with automatic reconnect and local BroadcastChannel mesh fallback.
 */

class ProctorSocket {
  /**
   * @param {Object} options
   * @param {'candidate'|'admin'} options.role
   * @param {string} [options.candidateId]
   * @param {string} [options.candidateName]
   * @param {string} [options.wsUrl]
   * @param {Function} [options.onMessage]
   * @param {Function} [options.onConnect]
   * @param {Function} [options.onDisconnect]
   */
  constructor(options = {}) {
    this.role = options.role || 'candidate';
    this.sessionId = options.sessionId || this._extractQueryParam('sessionId') || this._extractQueryParam('session_id') || 'default';
    this.candidateId = options.candidateId || this._extractQueryParam('candidateId') || this._extractQueryParam('candidate_id') || 'cand_' + Math.random().toString(36).substring(2, 9);
    this.candidateName = options.candidateName || this._extractQueryParam('name') || this._extractQueryParam('candidateName') || 'Candidate';
    this.wsUrl = options.wsUrl || this._determineDefaultWsUrl();
    this.onMessage = options.onMessage || null;
    this.onConnect = options.onConnect || null;
    this.onDisconnect = options.onDisconnect || null;

    this.socket = null;
    this.isConnected = false;
    this.reconnectTimer = null;
    this.broadcastChannel = null;

    // Initialize cross-tab mesh sync fallback
    if (typeof BroadcastChannel !== 'undefined') {
      this.broadcastChannel = new BroadcastChannel('proctor_guard_mesh');
      this.broadcastChannel.onmessage = (event) => {
        this._handleIncomingMessage(event.data, 'broadcast');
      };
    }
  }

  _extractQueryParam(key) {
    if (typeof window === 'undefined' || !window.location || !window.location.search) return null;
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(key);
  }

  _determineDefaultWsUrl() {
    const isHttps = typeof window !== 'undefined' && window.location.protocol === 'https:';
    const proto = isHttps ? 'wss:' : 'ws:';
    const host = (typeof window !== 'undefined' && window.location.host) ? window.location.host : 'localhost:8000';
    if (this.role === 'admin') {
      return `${proto}//${host}/ws/admin/${encodeURIComponent(this.sessionId)}`;
    }
    return `${proto}//${host}/ws/candidate/${encodeURIComponent(this.sessionId)}/${encodeURIComponent(this.candidateId)}`;
  }

  connect() {
    try {
      console.log(`ProctorSocket: Connecting ${this.role} to ${this.wsUrl}...`);
      this.socket = new WebSocket(this.wsUrl);

      this.socket.onopen = () => {
        this.isConnected = true;
        console.log(`ProctorSocket: Connected via WebSocket (${this.role})`);
        
        // Initial handshake
        this.send({
          type: 'HANDSHAKE',
          role: this.role,
          candidateId: this.candidateId,
          candidateName: this.candidateName,
          timestamp: new Date().toISOString()
        });

        if (this.onConnect) this.onConnect();
      };

      this.socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this._handleIncomingMessage(data, 'ws');
        } catch (e) {
          console.warn('ProctorSocket: Failed to parse message', event.data);
        }
      };

      this.socket.onclose = () => {
        this.isConnected = false;
        if (this.onDisconnect) this.onDisconnect();
        this._scheduleReconnect();
      };

      this.socket.onerror = (err) => {
        console.warn('ProctorSocket: WebSocket notice (mesh fallback active):', err.message || 'Connecting...');
      };
    } catch (err) {
      console.warn('ProctorSocket: WebSocket init notice, running on mesh channel:', err);
      this._scheduleReconnect();
    }
  }

  _scheduleReconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, 5000);
  }

  send(data) {
    const payload = {
      ...data,
      senderRole: this.role,
      candidateId: this.candidateId,
      timestamp: data.timestamp || new Date().toISOString()
    };

    // Send via live WebSocket if ready
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      try {
        this.socket.send(JSON.stringify(payload));
      } catch (err) {
        console.warn('ProctorSocket: Error sending WebSocket data', err);
      }
    }

    // Always mirror through local BroadcastChannel so dual tabs work even offline
    if (this.broadcastChannel) {
      try {
        this.broadcastChannel.postMessage(payload);
      } catch (e) {
        console.warn('ProctorSocket: Mesh broadcast error', e);
      }
    }
  }

  sendIncident(incident) {
    const payload = {
      sessionId: this.sessionId,
      candidateId: this.candidateId,
      timestamp: incident.timestamp || new Date().toISOString(),
      severity: incident.severity || 'MEDIUM',
      eventType: incident.eventType || incident.type || 'UNKNOWN',
      metadata: incident.metadata || { message: incident.message || '' },
      snapshotFrame: incident.snapshotFrame || incident.cameraSnapshot || null,
      type: 'incident'
    };
    this.send(payload);
    return payload;
  }

  _handleIncomingMessage(data, source) {
    // Prevent echo loops
    if (data.senderRole === this.role && data.candidateId === this.candidateId) {
      return;
    }

    if (typeof this.onMessage === 'function') {
      this.onMessage(data, source);
    }
  }

  disconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    if (this.broadcastChannel) {
      this.broadcastChannel.close();
      this.broadcastChannel = null;
    }
    this.isConnected = false;
  }
}

if (typeof window !== 'undefined') {
  window.ProctorSocket = ProctorSocket;
}
