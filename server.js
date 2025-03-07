const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const Joi = require('joi');
const bcrypt = require('bcrypt'); // Import bcrypt for password hashing

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(bodyParser.json());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    optionsSuccessStatus: 200
}));
app.use(helmet()); // Security enhancements with Helmet

// Validate environment variables
const envSchema = Joi.object({
    PORT: Joi.number().default(5000),
    FRONTEND_URL: Joi.string().uri().required(),
    MONGO_URI: Joi.string().uri().required(),
    EMAIL_USER: Joi.string().email().required(),
    EMAIL_PASS: Joi.string().required(),
    JWT_SECRET: Joi.string().required()
}).unknown();

const { error, value: envVars } = envSchema.validate(process.env);
if (error) {
    throw new Error(`Config validation error: ${error.message}`);
}

// Rate limiting for sensitive endpoints
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // Limit each IP to 100 requests per windowMs
});
app.use('/api/users/login', limiter);
app.use('/api/users/forgot-password', limiter);

// Configure the email transporter
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: envVars.EMAIL_USER,
        pass: envVars.EMAIL_PASS
    },
    socketTimeout: 60000,
    connectionTimeout: 60000
});

// Function to send the password reset email
const sendPasswordResetEmail = (email, token) => {
    const resetUrl = `${envVars.FRONTEND_URL}/reset-password?token=${token}`;
    const mailOptions = {
        from: envVars.EMAIL_USER,
        to: email,
        subject: 'Password Reset Request',
        text: `You requested a password reset. Click the link below to reset your password:\n\n${resetUrl}\n\nIf you did not request this, please ignore this email.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error sending password reset email:', error);
        } else {
            console.log('Password reset email sent:', info.response);
        }
    });
};

// MongoDB Connection with retry mechanism
const connectWithRetry = () => {
    mongoose.connect(envVars.MONGO_URI, {
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
    })
    .then(() => console.log('MongoDB connected...'))
    .catch(err => {
        console.error('MongoDB connection error:', err);
        console.log('Retrying connection in 5 seconds...');
        setTimeout(connectWithRetry, 5000); // Retry after 5 seconds
    });
};

connectWithRetry();

// User Schema and Model
const userSchema = new mongoose.Schema({
    FirstName: String,
    MiddleName: String,
    LastName: String,
    Role: String,
    Gender: String,
    Nationality: String,
    State: String,
    Pincode: String,
    Email: { type: String, unique: true },
    Password: String // Store hashed password
});
const User = mongoose.model('User', userSchema);

// Generate JWT Token
const generateToken = (user) => {
    return jwt.sign({ id: user._id, email: user.Email }, envVars.JWT_SECRET, { expiresIn: '1h' });
};

// Hash password before saving
const hashPassword = async (password) => {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
};

// Compare hashed password
const comparePassword = async (plainPassword, hashedPassword) => {
    return await bcrypt.compare(plainPassword, hashedPassword);
};

// Routes

/**
 * @route POST /api/users
 * @desc Create a new user
 */
app.post('/api/users', async (req, res) => {
    try {
        console.log('Received request to create user:', req.body);

        // Check if the email already exists
        const existingUser = await User.findOne({ Email: req.body.Email });
        if (existingUser) {
            console.log('Email already exists:', req.body.Email);
            return res.status(400).send({ error: "Email already exists" });
        }

        // Hash the password before saving
        const hashedPassword = await hashPassword(req.body.Password);
        const user = new User({ ...req.body, Password: hashedPassword });
        await user.save();
        console.log('User created successfully:', user);
        res.status(201).send(user);
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(400).send({ error: 'Failed to create user', details: error.message });
    }
});

/**
 * @route POST /api/users/login
 * @desc Login a user
 */
app.post('/api/users/login', async (req, res) => {
    try {
        const { Email, Password } = req.body;
        console.log('Received login request:', req.body);

        // Check if the user exists
        const user = await User.findOne({ Email });
        if (!user) {
            console.log('Email does not exist:', Email);
            return res.status(400).send({ error: "Invalid email or password" });
        }

        // Compare hashed passwords
        const isPasswordValid = await comparePassword(Password, user.Password);
        if (!isPasswordValid) {
            console.log('Invalid password for email:', Email);
            return res.status(400).send({ error: "Invalid email or password" });
        }

        // Generate JWT token
        const token = generateToken(user);
        console.log('User logged in successfully:', user);
        res.status(200).send({ user, token });
    } catch (error) {
        console.error('Error logging in user:', error);
        res.status(500).send({ error: 'Failed to login', details: error.message });
    }
});

/**
 * @route POST /api/users/forgot-password
 * @desc Send a password reset link to the user's email
 */
app.post('/api/users/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        console.log('Received forgot password request for email:', email);

        // Check if the user exists
        const user = await User.findOne({ Email: email });
        if (!user) {
            console.log('Email does not exist:', email);
            return res.status(400).send({ error: "Email not found" });
        }

        // Generate a password reset token
        const resetToken = jwt.sign({ email: user.Email }, envVars.JWT_SECRET, { expiresIn: '15m' });

        // Send the reset token to the user's email
        sendPasswordResetEmail(user.Email, resetToken);

        res.status(200).send({ message: "Password reset link sent to your email." });
    } catch (error) {
        console.error('Error handling forgot password:', error);
        res.status(500).send({ error: 'Failed to process forgot password request', details: error.message });
    }
});

/**
 * @route POST /api/users/reset-password
 * @desc Reset user password using the token
 */
app.post('/api/users/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        // Verify the token
        const decoded = jwt.verify(token, envVars.JWT_SECRET);
        console.log('Decoded token:', decoded);

        // Find the user
        const user = await User.findOne({ Email: decoded.email });
        if (!user) {
            return res.status(400).send({ error: "Invalid or expired token" });
        }

        // Hash the new password before saving
        const hashedPassword = await hashPassword(newPassword);
        user.Password = hashedPassword;
        await user.save();

        res.status(200).send({ message: "Password reset successfully" });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).send({ error: 'Failed to reset password', details: error.message });
    }
});

/**
 * @route GET /api/users/:email
 * @desc Fetch user details by email
 */
app.get('/api/users/:email', async (req, res) => {
    try {
        const email = req.params.email; // Get the email from the URL parameter
        console.log('Fetching user details for email:', email);

        // Find the user by email
        const user = await User.findOne({ Email: email });

        if (!user) {
            console.log('User not found for email:', email);
            return res.status(404).send({ error: "User not found" });
        }

        // Return the user details (excluding sensitive fields like password)
        const userDetails = {
            FirstName: user.FirstName,
            MiddleName: user.MiddleName,
            LastName: user.LastName,
            Role: user.Role,
            Gender: user.Gender,
            Nationality: user.Nationality,
            State: user.State,
            Pincode: user.Pincode,
            Email: user.Email,
        };

        console.log('User details fetched successfully:', userDetails);
        res.status(200).send(userDetails);
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).send({ error: 'Failed to fetch user details', details: error.message });
    }
});

// Centralized error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send({ error: 'Something went wrong!' });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
