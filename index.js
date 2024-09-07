const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));

// MySQL Database Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect(err => {
  if (err) throw err;
  console.log('MySQL Connected...');
});

// Express Session Setup
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true if using HTTPS
}));

// Serve Static Files
app.use(express.static('public'));

// Routes
// Homepage Route
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/home.html');
});

// Registration
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
    if (err) {
      console.log(err);
      res.send('User registration failed. Try again.');
    } else {
      res.redirect('/login.html');
    }
  });
});

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err) throw err;

    if (results.length > 0) {
      const user = results[0];
      const isMatch = await bcrypt.compare(password, user.password);

      if (isMatch) {
        req.session.loggedin = true;
        req.session.username = username;
        res.redirect('/dashboard');
      } else {
        res.send('Incorrect Username or Password!');
      }
    } else {
      res.send('Incorrect Username or Password!');
    }
  });
});

// Dashboard (Protected Route)
app.get('/dashboard', (req, res) => {
  if (req.session.loggedin) {
    res.send(`<h1 text-align="center">Welcome,${req.session.username}!</h1> <a href='/logout'>Logout</a>`);
  } else {
    res.redirect('/login.html');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) throw err;
    res.redirect('/login.html');
  });
});

// Start Server
app.listen(8082, () => {
  console.log('Server running at http://localhost:8082');
})