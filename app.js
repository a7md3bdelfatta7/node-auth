const express = require('express');
const app = express();
const db = require('./db');  // Import the database connection
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const moment = require('moment'); // For handling dates

app.use(express.json());  // To parse JSON bodies

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    req.user = user; // The JWT payload including roles
    next();
  });
}

// Example of using the database connection in a route
app.get('/example', (req, res) => {
  const sql = 'SELECT * FROM users'; // Replace with your query
  db.query(sql, (err, results) => {
    if (err) {
      return res.status(500).send('Database query error');
    }
    res.json(results);
  });
});


app.post('/register', (req, res) => {
  const { username, password , roles } = req.body;

  if (!username || !password) {
    return res.status(400).send('Username and password are required');
  }

  // Hash the password
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) throw err;

    // Insert user into database
    const sql = 'INSERT INTO users (username, password, roles) VALUES (?, ?, ?)';
    db.query(sql, [username, hashedPassword, roles], (err, result) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).send('Username already exists');
        }
        throw err;
      }
      res.status(201).send('User registered successfully');
    });
  });
});


app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Username and password are required');
  }

  const sql = 'SELECT * FROM users WHERE username = ?';
  db.query(sql, [username], (err, results) => {
    if (err) throw err;

    if (results.length === 0) {
      return res.status(401).send('Invalid credentials');
    }

    const user = results[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) throw err;

      if (!isMatch) {
        return res.status(401).send('Invalid credentials');
      }

      // Include roles in the JWT payload
      const payload = {
        id: user.id,
        username: user.username,
        roles: user.roles // Add the user's roles here
      };

      // Generate JWT tokens
      const accessToken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
      const refreshToken = jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

      // Save the refresh token in the database
      const expiresAt = moment().add(7, 'days').format('YYYY-MM-DD HH:mm:ss');
      const insertTokenSql = 'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)';
      db.query(insertTokenSql, [user.id, refreshToken, expiresAt], (err, result) => {
        if (err) {
          console.error('Error saving refresh token:', err);
          return res.status(500).send('Internal server error');
        }

        res.json({
          accessToken,
          refreshToken
        });
      });
    });
  });
});


app.post('/token', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(401).send('Token is required');
  }

  jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.status(403).send('Invalid refresh token');
    }

    const checkTokenSql = 'SELECT * FROM refresh_tokens WHERE token = ? AND expires_at > NOW()';
    db.query(checkTokenSql, [token], (err, results) => {
      if (err) throw err;

      if (results.length === 0) {
        return res.status(403).send('Refresh token is either invalid or expired');
      }

      // Generate new access token with roles
      const newAccessToken = jwt.sign({ id: user.id, username: user.username, roles: user.roles }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });

      res.json({ accessToken: newAccessToken });
    });
  });
});


app.get('/protected', authenticateToken, (req, res) => {
  res.send(`Hello, ${req.user.username}. This is a protected route!`);
});

app.post('/logout', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(401).send('Token is required');
  }

  // Delete the refresh token from the database
  const deleteTokenSql = 'DELETE FROM refresh_tokens WHERE token = ?';
  db.query(deleteTokenSql, [token], (err, result) => {
    if (err) {
      console.error('Error deleting refresh token:', err);
      return res.status(500).send('Internal server error');
    }

    res.send('Logout successful');
  });
});

app.get('/admin', authenticateToken, (req, res) => {
  // Check if the user has the 'admin' role
  if (!req.user.roles.includes('admin')) {
    return res.status(403).send('Access denied: Admins only');
  }

  res.send('Welcome, Admin!');
});
