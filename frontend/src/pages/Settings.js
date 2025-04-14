import React, { useState, useEffect } from "react";
import axios from "axios";
import {
  Card,
  CardHeader,
  CardContent,
  CardFooter,
  CardTitle,
} from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { Alert, AlertTitle, AlertDescription } from "../components/ui/alert";
import { Switch } from "../components/ui/switch";
import { Separator } from "../components/ui/separator";
import {
  ExclamationTriangleIcon,
  CheckCircledIcon,
} from "../components/ui/icons";

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:5000/api";

const Settings = () => {
  const [systemStatus, setSystemStatus] = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  // Form settings
  const [settings, setSettings] = useState({
    anomalyThreshold: -0.3,
    attackThreshold: 0.7,
    captureInterface: "",
    captureFilter: "",
    enableHttpLogging: true,
    enableDnsLogging: true,
  });

  useEffect(() => {
    // Load system status and settings
    loadSystemStatus();
  }, []);

  const loadSystemStatus = async () => {
    try {
      setLoading(true);

      const response = await axios.get(`${API_URL}/system/status`);
      setSystemStatus(response.data);

      // In a real system, we'd have an endpoint to get settings
      // For now, we'll just use defaults or extract from system status

      setError(null);
    } catch (err) {
      console.error("Error loading system status:", err);
      setError("Failed to load system status. Please check your connection.");
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (name, value) => {
    setSettings({
      ...settings,
      [name]: value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSuccess(null);
    setError(null);

    try {
      setSaving(true);

      // In a real system, we'd send all settings to an API endpoint
      // For this demo, we'll just update the detection thresholds, which our backend supports

      // Example API call - in a real implementation these would be proper endpoints
      await axios.post(`${API_URL}/system/settings`, {
        anomaly_threshold: settings.anomalyThreshold,
        attack_threshold: settings.attackThreshold,
      });

      setSuccess("Settings saved successfully");
    } catch (err) {
      console.error("Error saving settings:", err);
      setError("Failed to save settings. Please try again.");
    } finally {
      setSaving(false);
    }
  };

  // Restart the system (stop and then start)
  const handleRestartSystem = async () => {
    try {
      setLoading(true);
      setError(null);

      // Stop system if running
      if (systemStatus.system?.status === "running") {
        await axios.post(`${API_URL}/system/stop`);
      }

      // Wait a moment for cleanup
      await new Promise((resolve) => setTimeout(resolve, 1000));

      // Start system
      await axios.post(`${API_URL}/system/start`);

      // Refresh system status
      await loadSystemStatus();

      setSuccess("System restarted successfully");
    } catch (err) {
      console.error("Error restarting system:", err);
      setError("Failed to restart system. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6">
      <Card className="shadow-sm">
        <CardHeader>
          <CardTitle>System Settings</CardTitle>
        </CardHeader>

        <CardContent>
          {error && (
            <Alert variant="destructive" className="mb-4">
              <ExclamationTriangleIcon className="h-4 w-4" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {success && (
            <Alert
              variant="success"
              className="mb-4 bg-green-50 border-green-500 text-green-700"
            >
              <CheckCircledIcon className="h-4 w-4" />
              <AlertTitle>Success</AlertTitle>
              <AlertDescription>{success}</AlertDescription>
            </Alert>
          )}

          <form onSubmit={handleSubmit}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Detection Settings</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="anomalyThreshold">
                        Anomaly Threshold
                      </Label>
                      <span className="text-sm text-muted-foreground">
                        Current:{" "}
                        {systemStatus.components?.detector?.anomaly_threshold ||
                          -0.3}
                      </span>
                    </div>
                    <Input
                      id="anomalyThreshold"
                      type="number"
                      value={settings.anomalyThreshold}
                      onChange={(e) =>
                        handleInputChange(
                          "anomalyThreshold",
                          parseFloat(e.target.value)
                        )
                      }
                      step="0.1"
                      min="-1.0"
                      max="0.0"
                    />
                    <p className="text-sm text-muted-foreground">
                      Lower values are more sensitive to anomalies (recommended:
                      -0.3 to -0.5)
                    </p>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="attackThreshold">Attack Threshold</Label>
                      <span className="text-sm text-muted-foreground">
                        Current:{" "}
                        {systemStatus.components?.detector?.attack_threshold ||
                          0.7}
                      </span>
                    </div>
                    <Input
                      id="attackThreshold"
                      type="number"
                      value={settings.attackThreshold}
                      onChange={(e) =>
                        handleInputChange(
                          "attackThreshold",
                          parseFloat(e.target.value)
                        )
                      }
                      step="0.1"
                      min="0.0"
                      max="1.0"
                    />
                    <p className="text-sm text-muted-foreground">
                      Higher values reduce false positives (recommended: 0.6 to
                      0.8)
                    </p>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Capture Settings</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="captureInterface">Network Interface</Label>
                    <Input
                      id="captureInterface"
                      type="text"
                      value={settings.captureInterface}
                      onChange={(e) =>
                        handleInputChange("captureInterface", e.target.value)
                      }
                      placeholder="Leave empty for auto-select"
                    />
                    <p className="text-sm text-muted-foreground">
                      Specify network interface to capture packets (e.g., eth0)
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="captureFilter">Packet Filter</Label>
                    <Input
                      id="captureFilter"
                      type="text"
                      value={settings.captureFilter}
                      onChange={(e) =>
                        handleInputChange("captureFilter", e.target.value)
                      }
                      placeholder="E.g., tcp port 80"
                    />
                    <p className="text-sm text-muted-foreground">
                      BPF filter syntax to limit captured packets
                    </p>
                  </div>
                </CardContent>
              </Card>
            </div>

            <Card className="mb-6">
              <CardHeader>
                <CardTitle className="text-lg">Protocol Logging</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="flex items-center space-x-2">
                    <Switch
                      id="enableHttpLogging"
                      checked={settings.enableHttpLogging}
                      onCheckedChange={(checked) =>
                        handleInputChange("enableHttpLogging", checked)
                      }
                    />
                    <div className="space-y-1">
                      <Label htmlFor="enableHttpLogging">
                        Enable HTTP Content Logging
                      </Label>
                      <p className="text-sm text-muted-foreground">
                        Log HTTP requests and responses (can generate large
                        logs)
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <Switch
                      id="enableDnsLogging"
                      checked={settings.enableDnsLogging}
                      onCheckedChange={(checked) =>
                        handleInputChange("enableDnsLogging", checked)
                      }
                    />
                    <div className="space-y-1">
                      <Label htmlFor="enableDnsLogging">
                        Enable DNS Query Logging
                      </Label>
                      <p className="text-sm text-muted-foreground">
                        Log DNS queries and responses
                      </p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <div className="flex justify-between">
              <Button type="submit" disabled={saving || loading}>
                {saving ? "Saving..." : "Save Settings"}
              </Button>

              <Button
                variant="destructive"
                type="button"
                onClick={handleRestartSystem}
                disabled={loading}
              >
                Restart System
              </Button>
            </div>
          </form>
        </CardContent>

        <CardFooter className="text-sm text-muted-foreground">
          System status: {systemStatus.system?.status || "unknown"}
          {systemStatus.system?.uptime &&
            ` • Uptime: ${Math.floor(systemStatus.system.uptime / 60)} minutes`}
        </CardFooter>
      </Card>
    </div>
  );
};

export default Settings;
