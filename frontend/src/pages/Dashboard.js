import React, { useState, useEffect } from "react";
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

function Dashboard() {
  const [systemStatus, setSystemStatus] = useState("Healthy");
  const [cpuUsage, setCpuUsage] = useState(45);
  const [memoryUsage, setMemoryUsage] = useState(62);
  const [networkTraffic, setNetworkTraffic] = useState([]);
  const [recentAlerts, setRecentAlerts] = useState([
    {
      id: 1,
      type: "Warning",
      message: "Unusual traffic pattern detected",
      timestamp: "2025-04-14T10:23:18",
    },
    {
      id: 2,
      type: "Critical",
      message: "Potential port scanning attempt",
      timestamp: "2025-04-14T09:45:31",
    },
    {
      id: 3,
      type: "Info",
      message: "New device connected to network",
      timestamp: "2025-04-14T08:12:05",
    },
  ]);
  const [showToast, setShowToast] = useState(false);
  const [toastMessage, setToastMessage] = useState({});

  useEffect(() => {
    // Simulating data fetching
    const fetchData = async () => {
      // In a real implementation, these would be API calls
      // to the backend service
      try {
        // Fetch network traffic data
        // Fetch recent alerts
        // Fetch system metrics
        console.log("Dashboard data fetched");
      } catch (error) {
        console.error("Error fetching dashboard data:", error);
        showNotification({
          type: "destructive",
          title: "Connection Error",
          description: "Could not fetch dashboard data",
        });
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30 seconds

    return () => clearInterval(interval);
  }, []);

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
          <Button>Refresh Data</Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline">Actions</Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuLabel>Dashboard Actions</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() =>
                  showNotification({
                    type: "default",
                    title: "Network Scan",
                    description: "Starting network scan...",
                  })
                }
              >
                Run Network Scan
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() =>
                  showNotification({
                    type: "default",
                    title: "Configuration",
                    description: "Opening configuration panel...",
                  })
                }
              >
                Configure Settings
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() =>
                  showNotification({
                    type: "default",
                    title: "Report",
                    description: "Generating security report...",
                  })
                }
              >
                Generate Report
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
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-lg">CPU Usage</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span>{cpuUsage}%</span>
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
                <span>{memoryUsage}%</span>
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
            {recentAlerts.length === 0 ? (
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
            <div className="h-[300px] flex items-center justify-center border border-dashed rounded-lg">
              <p className="text-muted-foreground">
                Network traffic visualization will appear here
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export default Dashboard;
