const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory user database
let users = [];
let logs = [];

// Middleware
app.use(express.json());
app.use(cors());
app.use(session({ secret: "mySecretKey", resave: false, saveUninitialized: true }));
app.use(express.static(path.join(__dirname, "public")));

// Register User
app.post("/auth/register", async (req, res) => {
    const { name, email, password } = req.body;
    if (users.some(user => user.email === email)) {
        return res.status(400).json({ error: "User already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ name, email, password: hashedPassword });
    res.json({ message: "User registered successfully" });
});

// Login User
app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(user => user.email === email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ error: "Invalid credentials" });
    }
    req.session.user = user;
    logs.push({ email, action: "Logged in", time: new Date().toISOString() });
    res.json({ message: "Login successful" });
});

// User Dashboard
app.get("/user-dashboard", (req, res) => {
    if (!req.session.user) return res.redirect("/");
    res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// History Logs
app.get("/user-dashboard/history", (req, res) => {
    if (!req.session.user) return res.redirect("/");
    const userLogs = logs.filter(log => log.email === req.session.user.email);
    res.json(userLogs);
});

// Logout
app.get("/logout", (req, res) => {
    logs.push({ email: req.session.user.email, action: "Logged out", time: new Date().toISOString() });
    req.session.destroy(() => res.redirect("/"));
});

// Start server
app.listen(PORT, () => console.log(` Server running on http://localhost:${PORT}`));
