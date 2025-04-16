import axios from "axios";

// New serverless API URL - for local development
const API_URL = process.env.REACT_APP_API_URL || "http://localhost:3000/api";

class AuthService {
  async login(username, password) {
    try {
      const response = await axios.post(`${API_URL}/auth`, {
        username,
        password,
        action: "login",
      });

      if (response.data.token) {
        localStorage.setItem("user", JSON.stringify(response.data));
        this.setAuthHeader(response.data.token);
        return true;
      }

      return false;
    } catch (error) {
      console.error("Login error:", error);
      throw error;
    }
  }

  async register(username, password, orgName = null) {
    try {
      const response = await axios.post(`${API_URL}/auth`, {
        username,
        password,
        orgName,
        action: "register",
      });

      if (response.data.token) {
        localStorage.setItem("user", JSON.stringify(response.data));
        this.setAuthHeader(response.data.token);
        return response.data;
      }

      return null;
    } catch (error) {
      console.error("Registration error:", error);
      throw error;
    }
  }

  async refreshToken() {
    try {
      const user = this.getCurrentUser();

      if (!user || !user.refreshToken) {
        return false;
      }

      const response = await axios.post(`${API_URL}/auth`, {
        username: user.user.username,
        refreshToken: user.refreshToken,
        action: "refresh",
      });

      if (response.data.token) {
        // Update stored user with new tokens
        localStorage.setItem("user", JSON.stringify(response.data));
        this.setAuthHeader(response.data.token);
        return true;
      }

      return false;
    } catch (error) {
      console.error("Token refresh error:", error);
      // If refresh fails, logout
      this.logout();
      return false;
    }
  }

  logout() {
    localStorage.removeItem("user");
    delete axios.defaults.headers.common["Authorization"];
  }

  getCurrentUser() {
    const userStr = localStorage.getItem("user");
    if (!userStr) return null;

    try {
      return JSON.parse(userStr);
    } catch (e) {
      return null;
    }
  }

  getToken() {
    const user = this.getCurrentUser();
    return user ? user.token : null;
  }

  getApiKey() {
    const user = this.getCurrentUser();
    return user && user.org ? user.org.apiKey : null;
  }

  getOrgId() {
    const user = this.getCurrentUser();
    return user && user.user ? user.user.orgId : null;
  }

  setAuthHeader(token) {
    if (token) {
      axios.defaults.headers.common["Authorization"] = `Bearer ${token}`;
    } else {
      delete axios.defaults.headers.common["Authorization"];
    }
  }

  async isAuthenticated() {
    const token = this.getToken();

    if (!token) {
      return false;
    }

    this.setAuthHeader(token);

    try {
      // Test token validity by making a request to a protected endpoint
      await axios.get(`${API_URL}/dashboard-data?endpoint=status`);
      return true;
    } catch (error) {
      if (
        error.response &&
        (error.response.status === 401 || error.response.status === 403)
      ) {
        // Try to refresh the token
        const refreshSuccess = await this.refreshToken();
        if (refreshSuccess) {
          return true;
        }

        // If refresh fails, logout
        this.logout();
      }
      return false;
    }
  }
}

// Create a singleton instance
const authServiceInstance = new AuthService();

// Set auth header if a token exists
const token = authServiceInstance.getToken();
if (token) {
  authServiceInstance.setAuthHeader(token);
}

// Add axios interceptor to handle token expiration
axios.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // If error is 401 and we haven't tried to refresh yet
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        // Try to refresh the token
        const refreshed = await authServiceInstance.refreshToken();

        if (refreshed) {
          // Set new auth header for the request
          originalRequest.headers[
            "Authorization"
          ] = `Bearer ${authServiceInstance.getToken()}`;
          // Retry the original request
          return axios(originalRequest);
        }
      } catch (e) {
        // Refresh failed, do nothing
      }
    }

    return Promise.reject(error);
  }
);

export default authServiceInstance;
