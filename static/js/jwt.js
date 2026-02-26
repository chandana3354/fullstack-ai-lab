/* =========================
   Global Variables
========================= */
let accessToken = null;
let refreshTokenValue = null;

const BASE_URL = "http://localhost:5000";

/* =========================
   Tab Switching
========================= */
function showTab(tab) {
  document
    .querySelectorAll(".tab-content")
    .forEach((t) => t.classList.remove("active"));

  document
    .querySelectorAll(".tab-btn")
    .forEach((b) => b.classList.remove("active"));

  if (tab === "login") {
    document.getElementById("loginTab").classList.add("active");
    document.querySelectorAll(".tab-btn")[0].classList.add("active");
  } else {
    document.getElementById("signupTab").classList.add("active");
    document.querySelectorAll(".tab-btn")[1].classList.add("active");
  }
}

/* =========================
   Message Display
========================= */
function showMessage(text, type) {
  const messageDiv = document.getElementById("message");
  messageDiv.textContent = text;
  messageDiv.className = `message ${type}`;
  messageDiv.style.display = "block";

  setTimeout(() => {
    messageDiv.style.display = "none";
  }, 5000);
}

/* =========================
   Signup
========================= */
document.getElementById("signupForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const email = document.getElementById("signupEmail").value;
  const password = document.getElementById("signupPassword").value;
  const confirmPassword = document.getElementById("signupConfirm").value;

  if (password !== confirmPassword) {
    showMessage("Passwords do not match", "error");
    return;
  }

  if (password.length < 6) {
    showMessage("Password must be at least 6 characters", "error");
    return;
  }

  try {
    const response = await fetch(`${BASE_URL}/api/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    const data = await response.json();

    if (response.ok) {
      showMessage("Registration successful! Please login.", "success");
      document.getElementById("signupForm").reset();
      showTab("login");
    } else {
      showMessage(data.error || "Signup failed", "error");
    }
  } catch (error) {
    showMessage("Error: " + error.message, "error");
  }
});

/* =========================
   Login
========================= */
document.getElementById("loginForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();

  const email = document.getElementById("loginEmail").value;
  const password = document.getElementById("loginPassword").value;

  try {
    const response = await fetch(`${BASE_URL}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    const data = await response.json();

    if (response.ok) {
      accessToken = data.access_token;
      refreshTokenValue = data.refresh_token;

      document.getElementById("authSection").style.display = "none";
      document.getElementById("dashboardSection").style.display = "block";
      document.getElementById("userEmail").textContent = data.user;

      document.getElementById("accessTokenDisplay").textContent =
        accessToken.substring(0, 50) + "...";

      document.getElementById("refreshTokenDisplay").textContent =
        refreshTokenValue.substring(0, 50) + "...";

      showMessage("Login successful!", "success");
    } else {
      showMessage(data.error || "Login failed", "error");
    }
  } catch (error) {
    showMessage("Error: " + error.message, "error");
  }
});

/* =========================
   Protected Route Test
========================= */
async function testProtectedRoute() {
  try {
    const response = await fetch(`${BASE_URL}/api/protected`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    const data = await response.json();

    const responseArea = document.getElementById("responseArea");
    responseArea.style.display = "block";
    responseArea.innerHTML = `
            <h3>Protected Route Response:</h3>
            <pre>${JSON.stringify(data, null, 2)}</pre>
        `;

    if (response.ok) {
      showMessage("Access granted!", "success");
    } else {
      showMessage("Access denied: " + data.error, "error");
    }
  } catch (error) {
    showMessage("Error: " + error.message, "error");
  }
}

/* =========================
   Refresh Token
========================= */
async function refreshToken() {
  try {
    const response = await fetch(`${BASE_URL}/api/refresh`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${refreshTokenValue}`,
      },
    });

    const data = await response.json();

    if (response.ok) {
      accessToken = data.access_token;
      document.getElementById("accessTokenDisplay").textContent =
        accessToken.substring(0, 50) + "...";

      showMessage("Token refreshed successfully!", "success");
    } else {
      showMessage("Failed to refresh token", "error");
    }
  } catch (error) {
    showMessage("Error: " + error.message, "error");
  }
}

/* =========================
   Logout
========================= */
async function logout() {
  try {
    const response = await fetch(`${BASE_URL}/api/logout`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (response.ok) {
      accessToken = null;
      refreshTokenValue = null;

      document.getElementById("authSection").style.display = "block";
      document.getElementById("dashboardSection").style.display = "none";
      document.getElementById("loginForm").reset();
      document.getElementById("responseArea").style.display = "none";

      showMessage("Logged out successfully!", "success");
    }
  } catch (error) {
    showMessage("Error: " + error.message, "error");
  }
}