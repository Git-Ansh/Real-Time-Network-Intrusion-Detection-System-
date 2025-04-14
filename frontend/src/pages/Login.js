import React, { useState } from "react";
import AuthService from "../utils/AuthService";
import { Card, CardContent, CardFooter, CardHeader } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { Button } from "../components/ui/button";
import { Alert, AlertTitle, AlertDescription } from "../components/ui/alert";
import { ExclamationTriangleIcon } from "../components/ui/icons";

const Login = ({ setIsAuthenticated }) => {
  const [credentials, setCredentials] = useState({
    username: "",
    password: "",
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setCredentials({
      ...credentials,
      [name]: value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const success = await AuthService.login(
        credentials.username,
        credentials.password
      );

      if (success) {
        setIsAuthenticated(true);
      } else {
        setError("Invalid login response");
      }
    } catch (err) {
      console.error("Login error:", err);
      setError(
        err.response?.data?.error ||
          "Login failed. Please check your credentials."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <div className="w-full max-w-md p-4">
        <Card className="shadow-lg">
          <CardHeader className="bg-primary text-white space-y-1 p-6">
            <div className="text-center">
              <h3 className="text-2xl font-bold text-white">Network Intrusion Detection System</h3>
              <p className="text-lg text-white">Login</p>
            </div>
          </CardHeader>
          <CardContent className="p-6 pt-4">
            {error && (
              <Alert variant="destructive" className="mb-4">
                <ExclamationTriangleIcon className="h-4 w-4" />
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  type="text"
                  name="username"
                  value={credentials.username}
                  onChange={handleChange}
                  required
                  autoFocus
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  name="password"
                  value={credentials.password}
                  onChange={handleChange}
                  required
                />
              </div>

              <Button 
                className="w-full" 
                type="submit" 
                disabled={loading}
              >
                {loading ? "Logging in..." : "Login"}
              </Button>
            </form>
          </CardContent>
          <CardFooter className="bg-gray-50 p-4 text-center text-sm text-muted-foreground">
            Default credentials: admin / password
          </CardFooter>
        </Card>
      </div>
    </div>
  );
};

export default Login;
