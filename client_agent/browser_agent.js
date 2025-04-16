/**
 * Browser Agent for Real-Time Network Intrusion Detection System
 *
 * This script collects browser metrics and network activity for anomaly detection.
 * It monitors XHR/Fetch requests, JavaScript errors, and performance metrics.
 */

class BrowserAgent {
  constructor(options = {}) {
    this.options = {
      apiKey: null,
      apiEndpoint: "/api/browser-ingest",
      batchSize: 10,
      sendInterval: 10000, // milliseconds
      isEnabled: true,
      debugMode: false,
      ...options,
    };

    this.metricsQueue = [];
    this.isInitialized = false;
    this.sessionId = this._generateSessionId();
    this.pageLoadId = this._generateId();
    this.patternDetector = new SecurityPatternDetector();
  }

  /**
   * Initialize the browser agent
   */
  init() {
    if (this.isInitialized) return;
    if (!this.options.apiKey) {
      this._log("Error: API key is required to initialize browser agent");
      return;
    }

    try {
      // Set up event listeners
      this._setupNetworkMonitoring();
      this._setupErrorMonitoring();
      this._setupPerformanceMonitoring();

      // Start the metrics sending interval
      this._startMetricsSender();

      // Record page load
      this._recordPageLoad();

      this.isInitialized = true;
      this._log("Browser agent initialized");
    } catch (error) {
      this._log(`Error initializing browser agent: ${error.message}`);
      console.error("Browser agent initialization error", error);
    }
  }

  /**
   * Setup monitoring for XHR and Fetch requests
   */
  _setupNetworkMonitoring() {
    // Monitor XMLHttpRequest
    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;
    const self = this;

    XMLHttpRequest.prototype.open = function (
      method,
      url,
      async,
      user,
      password
    ) {
      this._requestData = {
        method,
        url,
        startTime: performance.now(),
        type: "xhr",
      };
      originalXHROpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function (data) {
      if (this._requestData) {
        this._requestData.requestBody = self._safeStringify(data);

        this.addEventListener("load", function () {
          const endTime = performance.now();
          self._recordNetworkRequest({
            ...this._requestData,
            status: this.status,
            responseSize: this.responseText ? this.responseText.length : 0,
            endTime,
            totalTime: endTime - this._requestData.startTime,
            success: this.status >= 200 && this.status < 400,
          });
        });

        this.addEventListener("error", function () {
          const endTime = performance.now();
          self._recordNetworkRequest({
            ...this._requestData,
            status: 0,
            endTime,
            totalTime: endTime - this._requestData.startTime,
            success: false,
            error: "Network error",
          });
        });
      }

      originalXHRSend.apply(this, arguments);
    };

    // Monitor Fetch API
    const originalFetch = window.fetch;
    window.fetch = function (input, init) {
      const startTime = performance.now();
      const method = init && init.method ? init.method : "GET";
      const url = typeof input === "string" ? input : input.url;

      return originalFetch
        .apply(this, arguments)
        .then((response) => {
          const endTime = performance.now();
          const clone = response.clone();

          self._recordNetworkRequest({
            method,
            url,
            startTime,
            endTime,
            totalTime: endTime - startTime,
            status: clone.status,
            success: clone.ok,
            type: "fetch",
          });

          return response;
        })
        .catch((error) => {
          const endTime = performance.now();
          self._recordNetworkRequest({
            method,
            url,
            startTime,
            endTime,
            totalTime: endTime - startTime,
            success: false,
            error: error.message,
            type: "fetch",
          });

          throw error;
        });
    };
  }

  /**
   * Setup monitoring for JavaScript errors
   */
  _setupErrorMonitoring() {
    window.addEventListener("error", (event) => {
      this._recordError({
        message: event.message,
        source: event.filename,
        lineno: event.lineno,
        colno: event.colno,
        stack: event.error ? event.error.stack : null,
        timestamp: new Date().toISOString(),
        type: "uncaught_error",
      });
    });

    window.addEventListener("unhandledrejection", (event) => {
      this._recordError({
        message: event.reason
          ? event.reason.message
          : "Unhandled promise rejection",
        stack: event.reason ? event.reason.stack : null,
        timestamp: new Date().toISOString(),
        type: "unhandled_rejection",
      });
    });
  }

  /**
   * Setup monitoring for performance metrics
   */
  _setupPerformanceMonitoring() {
    // Monitor resource timing
    const observer = new PerformanceObserver((list) => {
      const entries = list.getEntries();
      for (const entry of entries) {
        if (
          entry.initiatorType === "fetch" ||
          entry.initiatorType === "xmlhttprequest"
        ) {
          continue; // Skip, already covered by network monitoring
        }

        // Record resource load time
        if (entry.entryType === "resource") {
          this._recordResourceTiming(entry);
        }
      }
    });

    try {
      observer.observe({ entryTypes: ["resource"] });
    } catch (e) {
      this._log("PerformanceObserver not supported");
    }
  }

  /**
   * Record page load performance metrics
   */
  _recordPageLoad() {
    window.addEventListener("load", () => {
      setTimeout(() => {
        const performanceMetrics = this._collectPerformanceMetrics();
        this._addToQueue({
          type: "page_load",
          url: window.location.href,
          timestamp: new Date().toISOString(),
          metrics: performanceMetrics,
          pageLoadId: this.pageLoadId,
          sessionId: this.sessionId,
        });
      }, 0);
    });
  }

  /**
   * Collect performance metrics from the browser
   */
  _collectPerformanceMetrics() {
    if (!performance || !performance.timing) {
      return {};
    }

    const timing = performance.timing;
    const navigationStart = timing.navigationStart;

    return {
      domComplete: timing.domComplete - navigationStart,
      domInteractive: timing.domInteractive - navigationStart,
      domContentLoadedEventEnd:
        timing.domContentLoadedEventEnd - navigationStart,
      loadEventEnd: timing.loadEventEnd - navigationStart,
      responseEnd: timing.responseEnd - navigationStart,
      connectEnd: timing.connectEnd - navigationStart,
      secureConnectionStart: timing.secureConnectionStart || 0,
      fetchStart: timing.fetchStart - navigationStart,
      requestStart: timing.requestStart - navigationStart,
      domLoading: timing.domLoading - navigationStart,
      navigationStart: navigationStart,
    };
  }

  /**
   * Record network request
   */
  _recordNetworkRequest(requestData) {
    // Check for suspicious patterns in URL
    const threatDetection = this.patternDetector.scanRequest(requestData);

    const metric = {
      type: "request",
      url: requestData.url,
      method: requestData.method,
      status: requestData.status,
      totalTime: requestData.totalTime,
      success: requestData.success,
      timestamp: new Date().toISOString(),
      pageLoadId: this.pageLoadId,
      sessionId: this.sessionId,
      potentialThreat: threatDetection.detected ? threatDetection : null,
    };

    if (requestData.error) {
      metric.error = requestData.error;
    }

    this._addToQueue(metric);
  }

  /**
   * Record JavaScript errors
   */
  _recordError(errorData) {
    this._addToQueue({
      type: "error",
      ...errorData,
      pageLoadId: this.pageLoadId,
      sessionId: this.sessionId,
    });
  }

  /**
   * Record resource timing information
   */
  _recordResourceTiming(entry) {
    this._addToQueue({
      type: "resource",
      name: entry.name,
      initiatorType: entry.initiatorType,
      duration: entry.duration,
      startTime: entry.startTime,
      timestamp: new Date().toISOString(),
      pageLoadId: this.pageLoadId,
      sessionId: this.sessionId,
    });
  }

  /**
   * Add custom metric
   * @param {string} name - Metric name
   * @param {any} value - Metric value
   * @param {object} options - Additional options
   */
  addMetric(name, value, options = {}) {
    this._addToQueue({
      type: "custom",
      name,
      value,
      ...options,
      timestamp: new Date().toISOString(),
      pageLoadId: this.pageLoadId,
      sessionId: this.sessionId,
    });
  }

  /**
   * Add event to metrics queue
   */
  _addToQueue(metric) {
    if (!this.options.isEnabled) return;

    try {
      // Add client info
      metric.userAgent = navigator.userAgent;
      metric.clientInfo = {
        screenWidth: window.screen.width,
        screenHeight: window.screen.height,
        viewportWidth: window.innerWidth,
        viewportHeight: window.innerHeight,
        devicePixelRatio: window.devicePixelRatio,
      };

      this.metricsQueue.push(metric);
      this._log("Metric added to queue", metric);

      // If we've reached batch size, send immediately
      if (this.metricsQueue.length >= this.options.batchSize) {
        this._sendMetrics();
      }
    } catch (error) {
      this._log(`Error adding metric to queue: ${error.message}`);
    }
  }

  /**
   * Start the interval for sending metrics
   */
  _startMetricsSender() {
    setInterval(() => {
      if (this.metricsQueue.length > 0) {
        this._sendMetrics();
      }
    }, this.options.sendInterval);

    // Also send on page unload if there are pending metrics
    window.addEventListener("beforeunload", () => {
      if (this.metricsQueue.length > 0) {
        // Use sendBeacon for best delivery chance during page unload
        this._sendMetricsWithBeacon();
      }
    });
  }

  /**
   * Send collected metrics to API endpoint
   */
  _sendMetrics() {
    if (this.metricsQueue.length === 0) return;

    const metrics = [...this.metricsQueue];
    this.metricsQueue = [];

    const payload = {
      metrics,
      apiKey: this.options.apiKey,
      timestamp: new Date().toISOString(),
    };

    fetch(this.options.apiEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    })
      .then((response) => response.json())
      .then((data) => {
        this._log("Metrics sent successfully", data);

        // If any attacks or anomalies were detected, log a warning
        if (data.attack_detected || data.anomaly_detected) {
          console.warn(
            "Security alert: Potential security issue detected by NIDS"
          );
        }
      })
      .catch((error) => {
        this._log(`Error sending metrics: ${error.message}`);
        // On failure, add metrics back to the queue
        this.metricsQueue = [...metrics, ...this.metricsQueue].slice(0, 1000); // Prevent queue from growing too large
      });
  }

  /**
   * Send metrics using navigator.sendBeacon (for page unload)
   */
  _sendMetricsWithBeacon() {
    if (this.metricsQueue.length === 0 || !navigator.sendBeacon) return;

    const metrics = [...this.metricsQueue];
    this.metricsQueue = [];

    const payload = {
      metrics,
      apiKey: this.options.apiKey,
      timestamp: new Date().toISOString(),
    };

    const blob = new Blob([JSON.stringify(payload)], {
      type: "application/json",
    });
    navigator.sendBeacon(this.options.apiEndpoint, blob);

    this._log("Metrics sent using sendBeacon");
  }

  /**
   * Generate a unique ID
   */
  _generateId() {
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(
      /[xy]/g,
      function (c) {
        const r = (Math.random() * 16) | 0;
        const v = c === "x" ? r : (r & 0x3) | 0x8;
        return v.toString(16);
      }
    );
  }

  /**
   * Generate a session ID
   */
  _generateSessionId() {
    // Try to get existing session ID from localStorage
    try {
      const storedSessionId = localStorage.getItem("nids_session_id");
      const sessionTimestamp = localStorage.getItem("nids_session_timestamp");

      // If we have a valid session ID that's less than 30 minutes old
      if (storedSessionId && sessionTimestamp) {
        const expiry = parseInt(sessionTimestamp, 10) + 30 * 60 * 1000;
        if (Date.now() < expiry) {
          return storedSessionId;
        }
      }
    } catch (e) {
      // localStorage might be disabled
    }

    // Otherwise generate a new session ID
    const newSessionId = this._generateId();

    try {
      localStorage.setItem("nids_session_id", newSessionId);
      localStorage.setItem("nids_session_timestamp", Date.now().toString());
    } catch (e) {
      // Ignore localStorage errors
    }

    return newSessionId;
  }

  /**
   * Log messages if in debug mode
   */
  _log(message, data) {
    if (this.options.debugMode) {
      if (data) {
        console.log(`[BrowserAgent] ${message}`, data);
      } else {
        console.log(`[BrowserAgent] ${message}`);
      }
    }
  }

  /**
   * Safely stringify objects for logging
   */
  _safeStringify(obj) {
    if (!obj) return null;
    try {
      if (typeof obj === "string") return obj.substring(0, 100);
      return JSON.stringify(obj).substring(0, 100);
    } catch (e) {
      return "[Object]";
    }
  }
}

/**
 * Security pattern detector for identifying potential threats
 */
class SecurityPatternDetector {
  constructor() {
    // Initialize patterns for common attacks
    this.patterns = {
      xss: [
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /javascript:/gi,
        /on\w+\s*=/gi,
      ],
      sqlInjection: [
        /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
        /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(\;))/i,
        /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
        /exec(\s|\+)+(s|x)p\w+/i,
      ],
      pathTraversal: [/(\.\.\/)/i, /(\.\.\\)/i, /(%2e%2e%2f)/i],
    };
  }

  /**
   * Scan a request for security threats
   */
  scanRequest(requestData) {
    const url = requestData.url || "";
    const body = requestData.requestBody || "";

    const threats = [];

    // Check URL for various attack patterns
    Object.entries(this.patterns).forEach(([attackType, patterns]) => {
      patterns.forEach((pattern) => {
        if (pattern.test(url)) {
          threats.push({
            type: attackType,
            location: "url",
            pattern: pattern.toString(),
          });
        }

        if (typeof body === "string" && pattern.test(body)) {
          threats.push({
            type: attackType,
            location: "body",
            pattern: pattern.toString(),
          });
        }
      });
    });

    return {
      detected: threats.length > 0,
      threats,
    };
  }
}

// Export for both browser and Node.js environments
if (typeof module !== "undefined" && module.exports) {
  module.exports = { BrowserAgent, SecurityPatternDetector };
} else {
  window.BrowserAgent = BrowserAgent;
  window.SecurityPatternDetector = SecurityPatternDetector;
}
