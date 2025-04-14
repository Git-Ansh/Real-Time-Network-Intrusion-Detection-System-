import React, { useState, useEffect } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";
import "./App.css";

// Import components
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Navigation from "./components/Navigation";
import TrafficMonitor from "./pages/TrafficMonitor";
import Alerts from "./pages/Alerts";
import Settings from "./pages/Settings";

// Auth service
import AuthService from "./utils/AuthService";

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Check if user is authenticated on component mount
    const checkAuth = async () => {
      const authenticated = await AuthService.isAuthenticated();
      setIsAuthenticated(authenticated);
      setIsLoading(false);
    };

    checkAuth();
  }, []);

  // Create a protected route component
  const ProtectedRoute = ({ children }) => {
    if (isLoading) return <div>Loading...</div>;

    if (!isAuthenticated) {
      return <Navigate to="/login" />;
    }

    return children;
  };

  return (
    <Router>
      <div className="App">
        {isAuthenticated && (
          <Navigation setIsAuthenticated={setIsAuthenticated} />
        )}

        <div className="container-fluid mt-3">
          <Routes>
            <Route
              path="/login"
              element={
                isAuthenticated ? (
                  <Navigate to="/" />
                ) : (
                  <Login setIsAuthenticated={setIsAuthenticated} />
                )
              }
            />
            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <Dashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/traffic"
              element={
                <ProtectedRoute>
                  <TrafficMonitor />
                </ProtectedRoute>
              }
            />
            <Route
              path="/alerts"
              element={
                <ProtectedRoute>
                  <Alerts />
                </ProtectedRoute>
              }
            />
            <Route
              path="/settings"
              element={
                <ProtectedRoute>
                  <Settings />
                </ProtectedRoute>
              }
            />
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </div>
      </div>
    </Router>
  );
}

export default App;
