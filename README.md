// ----- SETUP (Node.js) -----
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const helmet = require('helmet');
const validator = require('validator');
const fetch = require('node-fetch');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // set to true with HTTPS
}));

// Rate limiter
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many login attempts. Please try again later."
});

// Dummy DB
const users = {}; // In-memory store: username -> { hash, email, token }

// ----- HELPERS -----
const sendEmail = async (to, code) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to,
    subject: 'Your 2FA Code',
    text: `Your 2FA code is ${code}`
  });
};

const generateCode = () => Math.floor(100000 + Math.random() * 900000);

// ----- ROUTES -----

// Registration
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  if (!validator.isEmail(email) || !validator.isStrongPassword(password)) {
    return res.status(400).send('Invalid input');
  }
  const hash = await bcrypt.hash(password, 10);
  users[username] = { hash, email };
  res.send('User registered');
});

// Login (Step 1)
app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (!user || !(await bcrypt.compare(password, user.hash))) {
    return res.status(401).send('Invalid credentials');
  }
  const code = generateCode();
  req.session.tempUser = username;
  req.session.otp = code;
  await sendEmail(user.email, code);
  res.send('2FA code sent');
});

// Login (Step 2 - 2FA Verification)
app.post('/verify', (req, res) => {
  const { code } = req.body;
  if (parseInt(code) === req.session.otp) {
    req.session.user = req.session.tempUser;
    delete req.session.tempUser;
    delete req.session.otp;
    res.send('Login successful');
  } else {
    res.status(403).send('Invalid 2FA code');
  }
});

// Breach Check
app.get('/breach-check/:email', async (req, res) => {
  const email = req.params.email;
  const hash = crypto.createHash('sha1').update(email).digest('hex').toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  const text = await response.text();
  const found = text.includes(suffix);
  res.send(found ? 'Email found in breaches!' : 'Email is safe.');
});

// Dashboard (example)
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.status(401).send('Unauthorized');
  res.send(`Welcome ${req.session.user}`);
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));



—------------------------------------------------------------------------------------------------------------------
[Front End]
<!DOCTYPE html>
<html>
<head>
  <title>Register</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <form action="/register" method="POST">
    <h2>Register</h2>
    <input name="username" placeholder="Username" required />
    <input name="email" type="email" placeholder="Email" required />
    <input name="password" type="password" placeholder="Password" required />
    <button type="submit">Create Account</button>
    <a href="/">Already have an account?</a>
  </form>
</body>
</html>

—------------------------------------------------------------------------------------------------------------------

<!DOCTYPE html>
<html>
<head>
  <title>Login</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <form action="/login" method="POST">
    <h2>Login</h2>
    <input name="username" placeholder="Username" required />
    <input name="password" type="password" placeholder="Password" required />
    <button type="submit">Login</button>
    <a href="/register">Don't have an account?</a>
  </form>
</body>
</html>
—-----------------------------------------------------------------------------------------------------------------
<!DOCTYPE html>
<html>
<head>
  <title>Verify 2FA</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <form action="/verify" method="POST">
    <h2>Enter 2FA Code</h2>
    <input name="code" placeholder="6-digit code" required />
    <button type="submit">Verify</button>
  </form>
</body>
</html>

—------------------------------------------------------------------------------------------------------------------
<!DOCTYPE html>
<html>
<head>
  <title>Dashboard</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <form>
    <h2>Welcome!</h2>
    <p>You’re securely logged in.</p>
    <a href="/">Logout</a>
  </form>
</body>
</html>
—------------------------------------------------------------------------------------------------------------------
body {
  font-family: Arial, sans-serif;
  background: #f0f2f5;
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
}

form {
  background: white;
  padding: 2rem;
  border-radius: 8px;
  box-shadow: 0 0 10px rgba(0,0,0,0.1);
  display: flex;
  flex-direction: column;
  gap: 1rem;
  width: 300px;
  text-align: center;
}

input, button {
  padding: 0.75rem;
  font-size: 1rem;
}

a {
  margin-top: 1rem;
  display: inline-block;
  text-decoration: none;
  color: #007bff;
}

—------------------------------------------------------------------------------------------------------------------
