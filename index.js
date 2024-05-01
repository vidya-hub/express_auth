const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;

// Create and connect to SQLite database
const db = new sqlite3.Database("./database.db");

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Routes
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Please provide username and password" });
  }

  // Hash password
  const hashedPassword = bcrypt.hashSync(password, 10);
  const checkQuery = "SELECT * FROM users WHERE username = ?";
  db.get(checkQuery, [username], (err, existingUser) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ message: "Error registering user" });
    }
    if (existingUser) {
      return res.status(400).json({ message: "Username already exists" });
    }
    const query = "INSERT INTO users (username, password) VALUES (?, ?)";
    db.run(query, [username, hashedPassword], (err) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ message: "Error registering user" });
      }
      res.status(200).json({ message: "User registered successfully" });
    });
  });
  // Insert user into database
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Please provide username and password" });
  }

  // Check if user exists in database
  const query = "SELECT * FROM users WHERE username = ?";
  db.get(query, [username], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // Check password
    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    res.status(200).json({ message: "Login successful" });
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// // Create users table
// db.serialize(() => {
//   db.run(
//     "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)"
//   );
// });
