import React, { useState, useEffect } from "react";
import axios from "axios";
import {
  Card,
  CardHeader,
  CardContent,
  CardFooter,
  CardTitle,
} from "../components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../components/ui/table";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Alert, AlertTitle, AlertDescription } from "../components/ui/alert";
import { Checkbox } from "../components/ui/checkbox";
import { Label } from "../components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../components/ui/select";
import { ExclamationTriangleIcon } from "../components/ui/icons";

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:5000/api";

const Alerts = () => {
  const [detections, setDetections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState({
    anomaliesOnly: false,
    attacksOnly: false,
    limit: 50,
  });
  const [refreshInterval, setRefreshInterval] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  useEffect(() => {
    // Initial data load
    loadDetections();

    // Set up refresh interval if autoRefresh is enabled
    if (autoRefresh) {
      const interval = setInterval(loadDetections, 15000); // Refresh every 15 seconds
      setRefreshInterval(interval);
    }

    return () => {
      // Clean up interval on unmount
      if (refreshInterval) clearInterval(refreshInterval);
    };
  }, [filters, autoRefresh]);

  const loadDetections = async () => {
    try {
      setLoading(true);

      // Build query parameters
      const params = new URLSearchParams({
        limit: filters.limit,
        anomalies_only: filters.anomaliesOnly,
        attacks_only: filters.attacksOnly,
      });

      const response = await axios.get(
        `${API_URL}/data/detections?${params.toString()}`
      );
      setDetections(response.data);
      setError(null);
    } catch (err) {
      console.error("Error loading detections:", err);
      setError("Failed to load detections. Please check your connection.");
    } finally {
      setLoading(false);
    }
  };

  const handleFilterChange = (name, value) => {
    setFilters({
      ...filters,
      [name]: value,
    });
  };

  const toggleAutoRefresh = () => {
    // Clear existing interval if any
    if (refreshInterval) {
      clearInterval(refreshInterval);
      setRefreshInterval(null);
    }

    // Toggle state and set up new interval if enabling
    const newAutoRefresh = !autoRefresh;
    setAutoRefresh(newAutoRefresh);

    if (newAutoRefresh) {
      const interval = setInterval(loadDetections, 15000);
      setRefreshInterval(interval);
    }
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp * 1000).toLocaleString();
  };

  const getSeverityBadge = (detection) => {
    if (detection.is_attack) {
      return <Badge variant="destructive">Attack</Badge>;
    } else if (detection.is_anomaly) {
      return <Badge variant="warning">Anomaly</Badge>;
    } else {
      return <Badge variant="success">Normal</Badge>;
    }
  };

  const getScoreBadge = (score, threshold, inverted = false) => {
    // For anomaly score, lower is more anomalous
    if (inverted) {
      if (score < threshold) {
        return <Badge variant="destructive">{score.toFixed(3)}</Badge>;
      } else {
        return <Badge variant="outline">{score.toFixed(3)}</Badge>;
      }
    }
    // For attack probability, higher is more likely an attack
    else {
      if (score > threshold) {
        return <Badge variant="destructive">{score.toFixed(3)}</Badge>;
      } else {
        return <Badge variant="outline">{score.toFixed(3)}</Badge>;
      }
    }
  };

  return (
    <div className="p-6">
      <div className="space-y-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Detection Alerts</CardTitle>
            <div className="flex space-x-2">
              <Button
                variant="default"
                size="sm"
                onClick={loadDetections}
                disabled={loading}
              >
                Refresh
              </Button>
              <Button
                variant={autoRefresh ? "default" : "outline"}
                size="sm"
                onClick={toggleAutoRefresh}
              >
                {autoRefresh ? "Auto-Refresh On" : "Auto-Refresh Off"}
              </Button>
            </div>
          </CardHeader>

          <CardContent>
            {error && (
              <Alert variant="destructive" className="mb-4">
                <ExclamationTriangleIcon className="h-4 w-4" />
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Card className="mb-4 bg-muted/50">
              <CardContent className="p-4">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="anomaliesOnly"
                      checked={filters.anomaliesOnly}
                      onCheckedChange={(checked) =>
                        handleFilterChange("anomaliesOnly", checked)
                      }
                    />
                    <Label htmlFor="anomaliesOnly">Show Anomalies Only</Label>
                  </div>

                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="attacksOnly"
                      checked={filters.attacksOnly}
                      onCheckedChange={(checked) =>
                        handleFilterChange("attacksOnly", checked)
                      }
                    />
                    <Label htmlFor="attacksOnly">Show Attacks Only</Label>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="limit">Results Limit</Label>
                    <Select
                      value={filters.limit.toString()}
                      onValueChange={(value) =>
                        handleFilterChange("limit", parseInt(value))
                      }
                    >
                      <SelectTrigger id="limit" className="w-full">
                        <SelectValue placeholder="Select limit" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="10">10</SelectItem>
                        <SelectItem value="50">50</SelectItem>
                        <SelectItem value="100">100</SelectItem>
                        <SelectItem value="500">500</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="flex items-end">
                    <Button
                      variant="outline"
                      onClick={() => {
                        setFilters({
                          anomaliesOnly: false,
                          attacksOnly: false,
                          limit: 50,
                        });
                      }}
                    >
                      Reset Filters
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>

            <div className="border rounded-md">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Anomaly Score</TableHead>
                    <TableHead>Attack Probability</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loading && detections.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center">
                        Loading...
                      </TableCell>
                    </TableRow>
                  ) : detections.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center">
                        No detections found.
                      </TableCell>
                    </TableRow>
                  ) : (
                    detections.map((detection, index) => (
                      <TableRow
                        key={index}
                        className={
                          detection.is_attack
                            ? "bg-red-50"
                            : detection.is_anomaly
                            ? "bg-yellow-50"
                            : ""
                        }
                      >
                        <TableCell>
                          {formatTimestamp(detection.timestamp)}
                        </TableCell>
                        <TableCell>{getSeverityBadge(detection)}</TableCell>
                        <TableCell>{detection.attack_type || "N/A"}</TableCell>
                        <TableCell>
                          {getScoreBadge(detection.anomaly_score, -0.3, true)}
                        </TableCell>
                        <TableCell>
                          {getScoreBadge(detection.attack_probability, 0.7)}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </CardContent>

          <CardFooter className="text-sm text-muted-foreground">
            Showing {detections.length} results.
            {autoRefresh && " Auto-refreshing every 15 seconds."}
          </CardFooter>
        </Card>
      </div>
    </div>
  );
};

export default Alerts;
