async function login() {
  const username = document.getElementById("username")?.value.trim() || "";
  const password = document.getElementById("password")?.value.trim() || "";
  const msg = document.getElementById("msg");

  if (msg) {
    msg.textContent = "";
    msg.className = "form-message";
  }

  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ username, password })
    });

    const data = await res.json();

    if (res.ok) {
      if (msg) {
        msg.textContent = "Login successful. Redirecting...";
        msg.className = "form-message success-message";
      }
      setTimeout(() => {
        window.location.href = "/";
      }, 600);
    } else {
      if (msg) {
        msg.textContent = data.error || "Login failed";
        msg.className = "form-message error-message";
      }
    }
  } catch (error) {
    if (msg) {
      msg.textContent = "Server error. Please try again.";
      msg.className = "form-message error-message";
    }
  }
}

async function register() {
  const full_name = document.getElementById("full_name")?.value.trim() || "";
  const username = document.getElementById("username")?.value.trim() || "";
  const email = document.getElementById("email")?.value.trim() || "";
  const password = document.getElementById("password")?.value.trim() || "";
  const msg = document.getElementById("msg");

  if (msg) {
    msg.textContent = "";
    msg.className = "form-message";
  }

  try {
    const res = await fetch("/api/register", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ full_name, username, email, password })
    });

    const data = await res.json();

    if (res.ok) {
      if (msg) {
        msg.textContent = "Registration successful. Redirecting to login...";
        msg.className = "form-message success-message";
      }
      setTimeout(() => {
        window.location.href = "/login";
      }, 800);
    } else {
      if (msg) {
        msg.textContent = data.error || "Registration failed";
        msg.className = "form-message error-message";
      }
    }
  } catch (error) {
    if (msg) {
      msg.textContent = "Server error. Please try again.";
      msg.className = "form-message error-message";
    }
  }
}