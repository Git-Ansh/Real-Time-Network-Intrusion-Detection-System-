import axios from "axios";

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:5001/api";

class AuthService {
  async login(username, password) {
    try {
      const response = await axios.post(`${API_URL}/auth/login`, {
        username,
        password,
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

  logout() {
    localStorage.removeItem("user");
    delete axios.defaults.headers.common["Authorization"];
  }

  getCurrentUser() {
    return JSON.parse(localStorage.getItem("user"));
  }

  getToken() {
    const user = this.getCurrentUser();
    return user ? user.token : null;
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
      await axios.get(`${API_URL}/system/status`);
      return true;
    } catch (error) {
      // If token is invalid, remove it and return false
      if (
        error.response &&
        (error.response.status === 401 || error.response.status === 403)
      ) {
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

export default authServiceInstance;
