const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;
const secretKey = 'your_secret_key'; // Replace with your own secret key

// Middleware
app.use(bodyParser.json());

// In-memory user store (replace with a database in production)
const users = [];

// Sign-Up (POST)
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    const existingUser = users.find(user => user.username === username);
    if (existingUser) {
        return res.status(400).json({ error: 'Username already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { username, password: hashedPassword };
    users.push(newUser);
    res.status(201).json({ message: 'User created successfully' });
});

// Login (POST)
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    const user = users.find(user => user.username === username);
    if (!user) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }
    const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
    res.json({ token });
});

// Middleware to protect routes
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Protected route (GET)
app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});
app.get('/users',(req, res) => {
    res.json(users);
});


app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
