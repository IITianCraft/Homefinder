import axios from "axios";
import { getRefreshToken, setTokens, clearTokens } from "./authTokenStore";

export async function refreshToken() {
  const refresh = getRefreshToken();

  if (!refresh) {
    clearTokens();
    throw new Error("No refresh token found");
  }

  try {
    const res = await axios.post(
       `${process.env.REACT_APP_API_URL}/token/refresh/`,
      { refresh },
      { headers: { "Content-Type": "application/json" } }
    );

    const { access, refresh: newRefresh } = res.data;

    if (access) {
      setTokens({ access, refresh: newRefresh || refresh });
      return access;
    }

    throw new Error("Token refresh failed");
  } catch (err) {
    clearTokens();
    throw err;
  }
}
