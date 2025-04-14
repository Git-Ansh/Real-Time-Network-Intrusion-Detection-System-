import React, { useState, useEffect } from "react";
import axios from "axios";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Separator } from "../components/ui/separator";
import { Progress } from "../components/ui/progress";
import { Badge } from "../components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "../components/ui/dropdown-menu";
import {
  ToastProvider,
  Toast,
  ToastTitle,
  ToastDescription,
  ToastViewport,
} from "../components/ui/toast";

// API URL
const API_URL = process.env.REACT_APP_API_URL || "http://localhost:5001/api";

function Dashboard() {
  const [systemStatus, setSystemStatus] = useState("Loading...");
  const [systemDetails, setSystemDetails] = useState(null);
  const [cpuUsage, setCpuUsage] = useState(0);
  const [memoryUsage, setMemoryUsage] = useState(0);
  const [networkTraffic, setNetworkTraffic] = useState([]);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [showToast, setShowToast] = useState(false);
  const [toastMessage, setToastMessage] = useState({});
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Fetch data from backend
    const fetchData = async () => {
      setIsLoading(true);
      try {
        // Fetch system status
        const statusResponse = await axios.get(`${API_URL}/system/status`);
        const systemData = statusResponse.data;

        // Determine overall system status based on component statuses
        const snifferRunning = systemData.sniffer === "running";
        const processorRunning = systemData.processor === "running";
        const detectorRunning = systemData.detector === "running";

        let status = "Healthy";
        if (!snifferRunning || !processorRunning || !detectorRunning) {
          status = "Warning";
        }

        setSystemStatus(status);
        setSystemDetails(systemData);

        // Fetch system metrics (CPU, memory)
        const metricsResponse = await axios.get(`${API_URL}/system/metrics`);
        setCpuUsage(metricsResponse.data.cpu_percent || 0);
        setMemoryUsage(metricsResponse.data.memory_percent || 0);

        // Fetch recent detections/alerts
        const alertsResponse = await axios.get(`${API_URL}/detections/recent`);
        const formattedAlerts = alertsResponse.data.map((alert, index) => ({
          id: index,
          type: alert.is_attack
            ? "Critical"
            : alert.is_anomaly
            ? "Warning"
            : "Info",
          message: alert.attack_type
            ? `${alert.attack_type.replace("_", " ")} attack detected`
            : alert.is_anomaly
            ? "Network anomaly detected"
            : "Unusual traffic pattern",
          timestamp: new Date(alert.timestamp * 1000).toISOString(),
          score: alert.anomaly_score,
        }));

        setRecentAlerts(formattedAlerts);
      } catch (error) {
        console.error("Error fetching dashboard data:", error);
        showNotification({
          type: "destructive",
          title: "Connection Error",
          description: "Could not fetch dashboard data from server",
        });
        setSystemStatus("Error");
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 10000); // Refresh every 10 seconds

    return () => clearInterval(interval);
  }, []);

  const handleStartSystem = async () => {
    try {
      await axios.post(`${API_URL}/system/start`);
      showNotification({
        type: "default",
        title: "System Started",
        description: "Network monitoring system has been started",
      });
      // Refresh data immediately
      fetchData();
    } catch (error) {
      console.error("Error starting system:", error);
      showNotification({
        type: "destructive",
        title: "Error",
        description: "Could not start the system",
      });
    }
  };

  const handleStopSystem = async () => {
    try {
      await axios.post(`${API_URL}/system/stop`);
      showNotification({
        type: "default",
        title: "System Stopped",
        description: "Network monitoring system has been stopped",
      });
      // Refresh data immediately
      fetchData();
    } catch (error) {
      console.error("Error stopping system:", error);
      showNotification({
        type: "destructive",
        title: "Error",
        description: "Could not stop the system",
      });
    }
  };

  const fetchData = async () => {
    try {
      // Fetch system status
      const statusResponse = await axios.get(`${API_URL}/system/status`);
      const systemData = statusResponse.data;

      // Determine overall system status
      const snifferRunning = systemData.sniffer === "running";
      const processorRunning = systemData.processor === "running";
      const detectorRunning = systemData.detector === "running";

      let status = "Healthy";
      if (!snifferRunning || !processorRunning || !detectorRunning) {
        status = "Warning";
      }

      setSystemStatus(status);
      setSystemDetails(systemData);

      // Fetch system metrics
      const metricsResponse = await axios.get(`${API_URL}/system/metrics`);
      setCpuUsage(metricsResponse.data.cpu_percent || 0);
      setMemoryUsage(metricsResponse.data.memory_percent || 0);

      // Fetch recent detections/alerts
      const alertsResponse = await axios.get(`${API_URL}/detections/recent`);
      const formattedAlerts = alertsResponse.data.map((alert, index) => ({
        id: index,
        type: alert.is_attack
          ? "Critical"
          : alert.is_anomaly
          ? "Warning"
          : "Info",
        message: alert.attack_type
          ? `${alert.attack_type.replace("_", " ")} attack detected`
          : alert.is_anomaly
          ? "Network anomaly detected"
          : "Unusual traffic pattern",
        timestamp: new Date(alert.timestamp * 1000).toISOString(),
        score: alert.anomaly_score,
      }));

      setRecentAlerts(formattedAlerts);
    } catch (error) {
      console.error("Error fetching dashboard data:", error);
      showNotification({
        type: "destructive",
        title: "Connection Error",
        description: "Could not fetch dashboard data from server",
      });
      setSystemStatus("Error");
    }
  };

  const showNotification = ({ type, title, description }) => {
    setToastMessage({
      type,
      title,
      description,
    });
    setShowToast(true);
    setTimeout(() => setShowToast(false), 5000);
  };

  const getStatusColor = (status) => {
    switch (status) {
      case "Healthy":
        return "bg-green-500";
      case "Warning":
        return "bg-yellow-500";
      case "Critical":
        return "bg-red-500";
      case "Error":
        return "bg-red-500";
      case "Loading...":
        return "bg-blue-500";
      default:
        return "bg-blue-500";
    }
  };

  const getBadgeVariant = (type) => {
    switch (type) {
      case "Critical":
        return "destructive";
      case "Warning":
        return "warning";
      case "Info":
        return "secondary";
      default:
        return "default";
    }
  };

  return (
    <div className="p-6">
      <ToastProvider>
        {showToast && (
          <Toast variant={toastMessage.type}>
            <ToastTitle>{toastMessage.title}</ToastTitle>
            <ToastDescription>{toastMessage.description}</ToastDescription>
          </Toast>
        )}
        <ToastViewport />
      </ToastProvider>

      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">Network Dashboard</h1>

        <div className="flex space-x-4">
          <Button onClick={fetchData}>Refresh Data</Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline">System Control</Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuLabel>System Actions</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleStartSystem}>
                Start Monitoring
              </DropdownMenuItem>
              <DropdownMenuItem onClick={handleStopSystem}>
                Stop Monitoring
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() =>
                  showNotification({
                    type: "default",
                    title: "System Restarting",
                    description: "Restarting network monitoring system...",
                  })
                }
              >
                Restart System
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-lg">System Status</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <span>{systemStatus}</span>
              <div
                className={`w-3 h-3 rounded-full ${getStatusColor(
                  systemStatus
                )}`}
              ></div>
            </div>
            {systemDetails && (
              <div className="mt-4 text-sm text-muted-foreground">
                <p>Packet Sniffer: {systemDetails.sniffer}</p>
                <p>Packet Processor: {systemDetails.processor}</p>
                <p>Anomaly Detector: {systemDetails.detector}</p>
                {systemDetails.start_time && (
                  <p>
                    Running since:{" "}
                    {new Date(systemDetails.start_time * 1000).toLocaleString()}
                  </p>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-lg">CPU Usage</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span>{cpuUsage.toFixed(1)}%</span>
              </div>
              <Progress value={cpuUsage} />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-lg">Memory Usage</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span>{memoryUsage.toFixed(1)}%</span>
              </div>
              <Progress value={memoryUsage} />
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card className="col-span-1">
          <CardHeader>
            <CardTitle>Recent Alerts</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <p className="text-center py-4 text-muted-foreground">
                Loading...
              </p>
            ) : recentAlerts.length === 0 ? (
              <p className="text-center py-4 text-muted-foreground">
                No recent alerts
              </p>
            ) : (
              <div className="space-y-4">
                {recentAlerts.map((alert) => (
                  <div
                    key={alert.id}
                    className="flex items-start justify-between pb-4"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <Badge variant={getBadgeVariant(alert.type)}>
                          {alert.type}
                        </Badge>
                        <span className="text-sm text-muted-foreground">
                          {new Date(alert.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <p>{alert.message}</p>
                      {alert.score !== undefined && (
                        <p className="text-sm text-muted-foreground">
                          Anomaly score: {alert.score.toFixed(2)}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="col-span-1">
          <CardHeader>
            <CardTitle>Network Traffic</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <p className="text-center py-4 text-muted-foreground">
                Loading...
              </p>
            ) : (
              <div className="h-[300px] flex flex-col justify-center">
                {systemDetails && (
                  <div className="space-y-2 text-center">
                    <p className="text-2xl font-bold">
                      {systemDetails.packets_captured || 0}
                    </p>
                    <p className="text-muted-foreground">Packets Captured</p>

                    <div className="mt-4 grid grid-cols-2 gap-2">
                      <div>
                        <p className="text-lg font-semibold">
                          {systemDetails.packets_per_second || 0}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Packets/sec
                        </p>
                      </div>
                      <div>
                        <p className="text-lg font-semibold">
                          {systemDetails.anomalies_detected || 0}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Anomalies
                        </p>
                      </div>
                      <div>
                        <p className="text-lg font-semibold">
                          {systemDetails.attacks_detected || 0}
                        </p>
                        <p className="text-xs text-muted-foreground">Attacks</p>
                      </div>
                      <div>
                        <p className="text-lg font-semibold">
                          {systemDetails.active_flows || 0}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Active Flows
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export default Dashboard;
