const express = require("express");
const cors = require("cors");
const app = express();
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");

app.use(express.json());
app.use(cors()); // Enable CORS for all routes

// Function to open SQLite database connection
const openDatabase = () => {
  return new sqlite3.Database("users.db");
};

// Function to initialize the users table
const initializeUsersTable = (db) => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      mobile TEXT,
      email TEXT UNIQUE,
      password TEXT
    )
  `);
};

// Endpoint to handle user registration
app.post("/register", async (req, res) => {
  const { name, mobile, email, password } = req.body;

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Open database connection
  const db = openDatabase();

  // Insert user data into the database
  db.run(
    "INSERT INTO users (name, mobile, email, password) VALUES (?, ?, ?, ?)",
    [name, mobile, email, hashedPassword],
    (err) => {
      db.close(); // Close the database connection

      if (err) {
        console.error("Error registering user:", err);
        res.status(500).json({ error: "Failed to register user" });
        return;
      }

      res.status(200).json({ message: "User registered successfully" });
    }
  );
});

// Endpoint to handle user login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // Open database connection
  const db = openDatabase();

  // Retrieve user from the database based on the email
  db.get(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, row) => {
      db.close(); // Close the database connection

      if (err) {
        console.error("Error finding user:", err);
        res.status(500).json({ error: "Error finding user" });
        return;
      }

      if (!row) {
        res.status(401).json({ error: "Invalid credentials" });
        return;
      }

      // Compare passwords
      const match = await bcrypt.compare(password, row.password);

      if (!match) {
        res.status(401).json({ error: "Invalid credentials" });
        return;
      }

      res.status(200).json({ message: "Login successful" });
    }
  );
});

// Endpoint to get all users
app.get("/users", (req, res) => {
  // Open database connection
  const db = openDatabase();

  db.all("SELECT * FROM users", [], (err, rows) => {
    db.close(); // Close the database connection

    if (err) {
      console.error("Error getting user data:", err);
      res.status(500).json({ error: "Error getting user data" });
      return;
    }

    res.status(200).json({ users: rows });
  });
});

// Start the server
const PORT = 3005;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
