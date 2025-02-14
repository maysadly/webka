// Required dependencies
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcrypt');
const MongoStore = require('connect-mongo');
const path = require('path');

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use(express.static('public'));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        collectionName: 'sessions'
    }),
    cookie: {
        maxAge: 1000 * 60 * 60 * 24, // 24 hours
        secure: process.env.NODE_ENV === 'production'
    }
}));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    loginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date },
    profilePicture: { type: String }
});

const User = mongoose.model('User', userSchema);

// Middleware to check authentication
const isAuthenticated = (req, res, next) => {
    if (req.session.userId) {
        return next();
    }
    res.redirect('/login');
};

// Routes
app.get('/', (req, res) => {
    res.render('index', { user: req.session.user });
});

app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Validation
        if (!username || !email || !password) {
            return res.render('register', { 
                error: 'All fields are required' 
            });
        }
        
        if (password.length < 8) {
            return res.render('register', { 
                error: 'Password must be at least 8 characters long' 
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ 
            $or: [{ email }, { username }] 
        });
        
        if (existingUser) {
            return res.render('register', { 
                error: 'Username or email already exists' 
            });
        }

        // Hash password and create user
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            username,
            email,
            password: hashedPassword
        });
        
        await user.save();
        res.redirect('/login');
    } catch (error) {
        res.render('register', { 
            error: 'Registration failed. Please try again.' 
        });
    }
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.render('login', { 
                error: 'Invalid email or password' 
            });
        }

        // Check if account is locked
        if (user.lockUntil && user.lockUntil > Date.now()) {
            return res.render('login', { 
                error: 'Account is locked. Please try again later.' 
            });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            user.loginAttempts += 1;
            
            // Lock account after 5 failed attempts
            if (user.loginAttempts >= 5) {
                user.lockUntil = Date.now() + (30 * 60 * 1000); // Lock for 30 minutes
            }
            
            await user.save();
            
            return res.render('login', { 
                error: 'Invalid email or password' 
            });
        }

        // Reset login attempts on successful login
        user.loginAttempts = 0;
        user.lockUntil = null;
        await user.save();

        req.session.userId = user._id;
        req.session.user = {
            username: user.username,
            role: user.role
        };
        
        res.redirect('/dashboard');
    } catch (error) {
        res.render('login', { 
            error: 'Login failed. Please try again.' 
        });
    }
});

app.get('/dashboard', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        res.render('dashboard', { user });
    } catch (error) {
        res.redirect('/login');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/dashboard');
        }
        res.redirect('/login');
    });
});

app.get('/profile/edit', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        res.render('edit-profile', { 
            user,
            error: null,
            success: null
        });
    } catch (error) {
        res.redirect('/dashboard');
    }
});

app.post('/profile/edit', isAuthenticated, async (req, res) => {
    try {
        const { username, email, currentPassword, newPassword } = req.body;
        const user = await User.findById(req.session.userId);

        // Check if email or username is being changed
        if (email !== user.email || username !== user.username) {
            // Check if new email or username already exists
            const existingUser = await User.findOne({
                _id: { $ne: req.session.userId },
                $or: [
                    { email: email },
                    { username: username }
                ]
            });

            if (existingUser) {
                return res.render('edit-profile', {
                    user,
                    error: 'Username or email already exists',
                    success: null
                });
            }
        }

        // Verify current password if provided
        if (currentPassword) {
            const validPassword = await bcrypt.compare(currentPassword, user.password);
            if (!validPassword) {
                return res.render('edit-profile', {
                    user,
                    error: 'Current password is incorrect',
                    success: null
                });
            }

            // Update password if new password is provided
            if (newPassword) {
                if (newPassword.length < 8) {
                    return res.render('edit-profile', {
                        user,
                        error: 'New password must be at least 8 characters long',
                        success: null
                    });
                }
                user.password = await bcrypt.hash(newPassword, 10);
            }
        } else if (newPassword) {
            return res.render('edit-profile', {
                user,
                error: 'Current password is required to change password',
                success: null
            });
        }

        // Update user information
        user.username = username;
        user.email = email;
        await user.save();

        // Update session with new username
        req.session.user.username = username;

        res.render('edit-profile', {
            user,
            error: null,
            success: 'Profile updated successfully!'
        });
    } catch (error) {
        const user = await User.findById(req.session.userId);
        res.render('edit-profile', {
            user,
            error: 'Error updating profile',
            success: null
        });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});