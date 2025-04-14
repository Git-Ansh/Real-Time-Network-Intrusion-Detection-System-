import React, { useState, useEffect, useRef } from "react";
import axios from "axios";
import {
  Card,
  CardHeader,
  CardContent,
  CardFooter,
  CardTitle,
} from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Alert, AlertTitle, AlertDescription } from "../components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../components/ui/select";
import { ExclamationTriangleIcon } from "../components/ui/icons";
import * as d3 from "d3";

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:5001/api";

const TrafficMonitor = () => {
  const [packets, setPackets] = useState([]);
  const [protocolFilter, setProtocolFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [refreshInterval, setRefreshInterval] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Graph references
  const networkGraphRef = useRef(null);
  const timelineRef = useRef(null);

  // Dimensions
  const width = 800;
  const height = 500;

  useEffect(() => {
    // Initial data load
    loadPackets();

    // Set up refresh interval if autoRefresh is enabled
    if (autoRefresh) {
      const interval = setInterval(loadPackets, 5000); // Refresh every 5 seconds
      setRefreshInterval(interval);
    }

    return () => {
      // Clean up interval on unmount
      if (refreshInterval) clearInterval(refreshInterval);
    };
  }, [protocolFilter, autoRefresh]);

  // Effect for network graph
  useEffect(() => {
    if (packets.length > 0 && networkGraphRef.current) {
      drawNetworkGraph();
    }
  }, [packets]);

  // Effect for timeline
  useEffect(() => {
    if (packets.length > 0 && timelineRef.current) {
      drawTimeline();
    }
  }, [packets]);

  const loadPackets = async () => {
    try {
      setLoading(true);

      // Build query parameters
      const params = new URLSearchParams({
        limit: 100,
      });

      if (protocolFilter) {
        params.append("protocol", protocolFilter);
      }

      const response = await axios.get(
        `${API_URL}/data/packets?${params.toString()}`
      );
      setPackets(response.data);
      setError(null);
    } catch (err) {
      console.error("Error loading packets:", err);
      setError("Failed to load packet data. Please check your connection.");
    } finally {
      setLoading(false);
    }
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
      const interval = setInterval(loadPackets, 5000);
      setRefreshInterval(interval);
    }
  };

  const drawNetworkGraph = () => {
    // Clear previous visualization
    d3.select(networkGraphRef.current).selectAll("*").remove();

    // Extract unique IPs and create nodes
    const ips = new Set();
    packets.forEach((packet) => {
      if (packet.src_ip) ips.add(packet.src_ip);
      if (packet.dst_ip) ips.add(packet.dst_ip);
    });

    const nodes = Array.from(ips).map((ip) => ({ id: ip }));

    // Create links between IPs
    const links = [];
    const linkCounts = {};

    packets.forEach((packet) => {
      if (packet.src_ip && packet.dst_ip) {
        const linkKey = `${packet.src_ip}-${packet.dst_ip}`;

        if (linkCounts[linkKey]) {
          linkCounts[linkKey].count += 1;
          linkCounts[linkKey].protocols = [
            ...new Set([...linkCounts[linkKey].protocols, ...packet.protocols]),
          ];
        } else {
          linkCounts[linkKey] = {
            count: 1,
            protocols: packet.protocols,
          };
        }
      }
    });

    Object.entries(linkCounts).forEach(([key, data]) => {
      const [source, target] = key.split("-");
      links.push({
        source,
        target,
        value: data.count,
        protocols: data.protocols,
      });
    });

    // Create SVG
    const svg = d3
      .select(networkGraphRef.current)
      .attr("width", width)
      .attr("height", height);

    // Create tooltip
    const tooltip = d3
      .select("body")
      .append("div")
      .attr("class", "d3-tooltip")
      .style("position", "absolute")
      .style("padding", "6px")
      .style("background", "rgba(0, 0, 0, 0.7)")
      .style("color", "white")
      .style("border-radius", "4px")
      .style("pointer-events", "none")
      .style("font-size", "12px")
      .style("visibility", "hidden");

    // Create simulation
    const simulation = d3
      .forceSimulation(nodes)
      .force(
        "link",
        d3
          .forceLink(links)
          .id((d) => d.id)
          .distance(100)
      )
      .force("charge", d3.forceManyBody().strength(-200))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(30));

    // Draw links
    const link = svg
      .append("g")
      .attr("stroke", "#999")
      .attr("stroke-opacity", 0.6)
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke-width", (d) => Math.sqrt(d.value))
      .on("mouseover", (event, d) => {
        tooltip.style("visibility", "visible").html(`<strong>${d.source.id} → ${
          d.target.id
        }</strong><br/>
                Packets: ${d.value}<br/>
                Protocols: ${d.protocols.join(", ")}`);
      })
      .on("mousemove", (event) => {
        tooltip
          .style("top", event.pageY - 10 + "px")
          .style("left", event.pageX + 10 + "px");
      })
      .on("mouseout", () => {
        tooltip.style("visibility", "hidden");
      });

    // Draw nodes
    const node = svg
      .append("g")
      .attr("stroke", "#fff")
      .attr("stroke-width", 1.5)
      .selectAll("circle")
      .data(nodes)
      .join("circle")
      .attr("r", 10)
      .attr("fill", "#69b3a2")
      .call(drag(simulation))
      .on("mouseover", (event, d) => {
        tooltip
          .style("visibility", "visible")
          .html(`<strong>IP:</strong> ${d.id}`);

        link.style("stroke", (l) =>
          l.source.id === d.id || l.target.id === d.id ? "#ff0000" : "#999"
        );
      })
      .on("mousemove", (event) => {
        tooltip
          .style("top", event.pageY - 10 + "px")
          .style("left", event.pageX + 10 + "px");
      })
      .on("mouseout", () => {
        tooltip.style("visibility", "hidden");
        link.style("stroke", "#999");
      });

    // Add text labels
    const label = svg
      .append("g")
      .attr("class", "labels")
      .selectAll("text")
      .data(nodes)
      .enter()
      .append("text")
      .text((d) => d.id)
      .attr("text-anchor", "middle")
      .style("font-size", "8px")
      .style("fill", "#000")
      .style("pointer-events", "none");

    // Update node and link positions
    simulation.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);

      node.attr("cx", (d) => d.x).attr("cy", (d) => d.y);

      label.attr("x", (d) => d.x).attr("y", (d) => d.y + 15);
    });

    // Drag functionality
    function drag(simulation) {
      function dragstarted(event) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        event.subject.fx = event.subject.x;
        event.subject.fy = event.subject.y;
      }

      function dragged(event) {
        event.subject.fx = event.x;
        event.subject.fy = event.y;
      }

      function dragended(event) {
        if (!event.active) simulation.alphaTarget(0);
        event.subject.fx = null;
        event.subject.fy = null;
      }

      return d3
        .drag()
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended);
    }

    return () => {
      tooltip.remove();
    };
  };

  const drawTimeline = () => {
    // Clear previous visualization
    d3.select(timelineRef.current).selectAll("*").remove();

    // Sort packets by timestamp
    const sortedPackets = [...packets].sort(
      (a, b) => a.timestamp - b.timestamp
    );

    // Dimensions
    const margin = { top: 30, right: 30, bottom: 50, left: 50 };
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = 200 - margin.top - margin.bottom;

    // Get time domain
    const minTime = d3.min(sortedPackets, (d) => d.timestamp);
    const maxTime = d3.max(sortedPackets, (d) => d.timestamp);

    // Create scales
    const xScale = d3
      .scaleTime()
      .domain([new Date(minTime * 1000), new Date(maxTime * 1000)])
      .range([0, innerWidth]);

    const yScale = d3
      .scaleLinear()
      .domain([0, d3.max(sortedPackets, (d) => d.size)])
      .range([innerHeight, 0]);

    // Create SVG
    const svg = d3
      .select(timelineRef.current)
      .attr("width", width)
      .attr("height", 200)
      .append("g")
      .attr("transform", `translate(${margin.left}, ${margin.top})`);

    // Add X axis
    svg
      .append("g")
      .attr("transform", `translate(0, ${innerHeight})`)
      .call(d3.axisBottom(xScale).ticks(5))
      .selectAll("text")
      .style("text-anchor", "end")
      .attr("dx", "-.8em")
      .attr("dy", ".15em")
      .attr("transform", "rotate(-45)");

    // Add Y axis
    svg.append("g").call(d3.axisLeft(yScale));

    // Add circles
    svg
      .selectAll("circle")
      .data(sortedPackets)
      .join("circle")
      .attr("cx", (d) => xScale(new Date(d.timestamp * 1000)))
      .attr("cy", (d) => yScale(d.size))
      .attr("r", 3)
      .attr("fill", (d) => {
        if (d.protocols.includes("TCP")) return "#69b3a2";
        if (d.protocols.includes("UDP")) return "#404080";
        if (d.protocols.includes("HTTP")) return "#ff7f0e";
        if (d.protocols.includes("DNS")) return "#d62728";
        return "#aaa";
      });

    // Add X axis label
    svg
      .append("text")
      .attr("text-anchor", "end")
      .attr("x", innerWidth / 2 + margin.left)
      .attr("y", innerHeight + margin.top + 20)
      .text("Time");

    // Add Y axis label
    svg
      .append("text")
      .attr("text-anchor", "end")
      .attr("transform", "rotate(-90)")
      .attr("y", -margin.left + 15)
      .attr("x", -innerHeight / 2)
      .text("Packet Size");

    // Add legend
    const legendData = [
      { color: "#69b3a2", label: "TCP" },
      { color: "#404080", label: "UDP" },
      { color: "#ff7f0e", label: "HTTP" },
      { color: "#d62728", label: "DNS" },
      { color: "#aaa", label: "Other" },
    ];

    const legend = svg
      .append("g")
      .attr("transform", `translate(${innerWidth - 100}, 0)`);

    legendData.forEach((item, i) => {
      legend
        .append("circle")
        .attr("cx", 0)
        .attr("cy", i * 20)
        .attr("r", 6)
        .attr("fill", item.color);

      legend
        .append("text")
        .attr("x", 15)
        .attr("y", i * 20 + 4)
        .text(item.label)
        .style("font-size", "12px");
    });
  };

  return (
    <div className="p-6">
      {error && (
        <Alert variant="destructive" className="mb-4">
          <ExclamationTriangleIcon className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Card className="shadow-sm">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Network Traffic Monitor</CardTitle>
          <div className="flex space-x-2 items-center">
            <Select value={protocolFilter} onValueChange={setProtocolFilter}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="All Protocols" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="">All Protocols</SelectItem>
                <SelectItem value="IP">IP</SelectItem>
                <SelectItem value="TCP">TCP</SelectItem>
                <SelectItem value="UDP">UDP</SelectItem>
                <SelectItem value="HTTP">HTTP</SelectItem>
                <SelectItem value="DNS">DNS</SelectItem>
              </SelectContent>
            </Select>

            <Button
              variant="default"
              size="sm"
              onClick={loadPackets}
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
          <div className="space-y-8">
            <div>
              <h5 className="text-lg font-medium mb-2">
                Network Traffic Graph
              </h5>
              <p className="text-sm text-muted-foreground mb-4">
                Visualizes connections between hosts. Hover over nodes (IPs) and
                edges (connections) to see details.
              </p>
              <div className="flex justify-center">
                <svg
                  ref={networkGraphRef}
                  width={width}
                  height={height}
                  className="border rounded-md"
                ></svg>
              </div>
            </div>

            <div>
              <h5 className="text-lg font-medium mb-2">Packet Timeline</h5>
              <p className="text-sm text-muted-foreground mb-4">
                Visualizes packet size over time, colored by protocol.
              </p>
              <div className="flex justify-center">
                <svg
                  ref={timelineRef}
                  width={width}
                  height={200}
                  className="border rounded-md"
                ></svg>
              </div>
            </div>
          </div>
        </CardContent>

        <CardFooter className="text-sm text-muted-foreground">
          Showing {packets.length} packets
          {protocolFilter && ` filtered by ${protocolFilter} protocol`}.
          {autoRefresh && " Auto-refreshing every 5 seconds."}
        </CardFooter>
      </Card>
    </div>
  );
};

export default TrafficMonitor;
