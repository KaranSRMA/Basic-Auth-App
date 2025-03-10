const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');  // Import nodemailer
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = 5000;

app.use(express.static(path.join(__dirname, 'public')));

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log(err));

// User model
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    password: { type: String, required: true },
    resetAttempts: { type: Number, default: 0 },
    resetToken: String,
    resetTokenExpires: Date,
    verificationAttempts: { type: Number, default: 0 },
    verificationToken: String,
    verificationExpiry: Date,
    verified: { type: Boolean, default: false }
});

const User = mongoose.model('User', UserSchema);

function verifyToken(req, res, next) {
    const token = req.header('Authorization')?.replace('Bearer ', '');  // Get the token from the Authorization header

    if (!token) {
        return res.status(403).json({ message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, '9e4c3177c5a274da80e23e7c21a2cb67d29e6ab2544b3ff33b2062f38fd8905723c982eea276453c7b6b8b80b6b29edb');  // Verify token
        req.userId = decoded.userId;  // Store userId in request object
        next();  // Continue to the next middleware or route handler
    } catch (err) {
        return res.status(401).json({ message: 'Invalid token' });
    }
}

// Route to get user data
app.get('/user', verifyToken, async (req, res) => {

    try {
        const user = await User.findById(req.userId);  // Find user by the userId decoded from the token

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({
            username: user.username,
            email: user.email,
            phone: user.phone
        });
    } catch (err) {
        console.error('Error fetching user data:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Create a reusable transport object using Mailtrap SMTP service

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
        user: process.env.USER,  // Replace with your Mailtrap username
        pass: process.env.PASS   // Replace with your Mailtrap password
    }
});


// Forgot password route
app.post('/forgot-password', async (req, res) => {
    let { email } = req.body;
    email = email.trim();

    if (email === "") {
        return res.status(400).json({ message: 'This field cant be empty' })
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ message: 'Invalid email format' });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (user.resetAttempts >= 6) {
            return res.status(429).json({ message: 'Too many reset attempts. Try again later.' });
        }

        // Generate a secure reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        user.resetToken = resetToken;
        user.resetTokenExpires = Date.now() + 3600000; // 1 hour expiry
        await user.save();

        const resetLink = `https://basic-auth-app-six.vercel.app/reset?email=${email}&token=${resetToken}`;
        const htmlContent = `
        <html>
        <body>
            <h1>Welcome to Our Service</h1>
            <p>Hello,</p>
            <p>Click the link below to reset your password:</p>
            <a href="${resetLink}" target="_blank">Verify Account</a>
        </body>
        </html>
    `;
        // Send reset email using Mailtrap SMTP
        const mailOptions = {
            from: 'no@reply.com',  // Replace with your sender email
            to: email,
            subject: 'Password Reset Request',
            html: htmlContent
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending email:', error);
                return res.status(500).json({ message: 'Error sending email' });
            }

            console.log('Email sent:', info.response);
            res.status(200).json({ message: `Password reset link sent to ${email}` });
        });

        user.resetAttempts += 1;
        await user.save();
    } catch (error) {
        console.error('Error processing forgot password request:', error);
        res.status(500).json({ message: 'Error processing request' });
    }
});


app.get('/reset', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', '/reset.html'));
})

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', '/index.html'));
})

// Reset password route
app.post('/reset-password', async (req, res) => {
    let { email, token, newPassword } = req.body;
    email = email.trim();
    newPassword = newPassword.trim();

    if (email === "" || newPassword === "") {
        return res.status(400).json({ message: 'This field cant be empty' })
    }

    try {
        const user = await User.findOne({ email, resetToken: token });

        if (!user || user.resetTokenExpires < Date.now()) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;

        // Reset the reset token and expiry
        user.resetToken = undefined;
        user.resetTokenExpires = undefined;
        await user.save();

        res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ message: 'Error resetting password' });
    }
});



// Register route
app.post('/register', async (req, res) => {
    let { username, email, phone, password, confirmpassword } = req.body;
    username = username.trim();
    email = email.trim();
    phone = phone.trim();
    password = password.trim();
    confirmpassword = confirmpassword.trim();
    const usernameRegex = /^[a-zA-Z0-9_]+$/;

    if (email === "" || phone === "" || password === "" || username === "") {
        return res.status(400).json({ message: "Input field cant be empty" })
    }

    if (!usernameRegex.test(username)) {
        return res.status(400).json({ message: 'Username only contains letters, numbers and underscore' })
    }

    if (password.length < 6) {
        return res.status(400).json({ message: "Password must be at least 6 character long" })
    }

    // Check if user already exists
    const existingUser = await User.findOne({
        $or: [
            { email },
            { phone },
            { username }
        ]
    });
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationExpiry = Date.now() + 3600000; // 1 hour expiry

    const verifyLink = `https://basic-auth-app-six.vercel.app/verify?email=${email}&token=${verificationToken}`;
    const htmlContent = `
        <html>
        <body>
            <h1>Welcome to Our Service</h1>
            <p>Hello,</p>
            <p>Click the link below to verify your account:</p>
            <a href="${verifyLink}" target="_blank">Verify Account</a>
        </body>
        </html>
    `;

    const mailOptions = {
        from: 'no@reply.com',  // Replace with your sender email
        to: email,
        subject: 'Verification email',
        html: htmlContent
    };

    if (existingUser) {
        return res.status(409).json({ message: 'User already exists' }); // Return a JSON response
    }

    if (password !== confirmpassword) {
        return res.status(401).json({ message: 'Passwords do not match' }); // Return a JSON response
    }

    if (existingUser && existingUser.verificationAttempts >= 6) {
        return res.status(429).json({ message: 'Too many verification attempts. Try again later.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({ username, email, phone, password: hashedPassword, verificationToken, verificationExpiry });
        await newUser.save();

        await transporter.sendMail(mailOptions)
        newUser.verificationAttempts += 1
        await newUser.save()
        res.status(200).json({ message: 'Verification link send to your email' }); // Return a success response as JSON
    } catch (error) {
        console.error('Error registering user:', error); // Debugging
        res.status(500).json({ message: 'Error registering user. Please try again later.' }); // Return a JSON response
    }
});

// Login route
app.post('/login', async (req, res) => {
    let { username, password } = req.body;
    username = username.trim();
    password = password.trim();
    const usernameRegex = /^[a-zA-Z0-9_]+$/;

    if (!usernameRegex.test(username)) {
        return res.status(400).json({ message: 'Username only contains letters, numbers and underscore' })
    }

    // Ensure password and userIdentifier are provided
    if (!password || !username) {
        return res.status(400).json('Please provide email, username, or phone along with password');
    }

    let users;
    // Check if the userIdentifier is an email, username, or phone number and search accordingly
    if (username.includes('@')) {
        // If it looks like an email (contains '@'), search by email
        users = await User.findOne({ email: username });
    } else if (/^\+?\d+$/.test(username)) {
        // If it looks like a phone number (only digits and optional '+'), search by phone
        users = await User.findOne({ phone: username });
    } else {
        // Otherwise, assume it's a username and search by username
        users = await User.findOne({ username: username });
    }

    if (!users) return res.status(403).json({ message: 'User not found' });
    if (!users.verified) {
        return res.status(403).json({ message: 'User not verified' })
    }

    const isMatch = await bcrypt.compare(password, users.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    // Create JWT token
    const token = jwt.sign({ userId: users._id, email:users.email }, '9e4c3177c5a274da80e23e7c21a2cb67d29e6ab2544b3ff33b2062f38fd8905723c982eea276453c7b6b8b80b6b29edb', { expiresIn: '24h' });

    res.status(200).json({ token });
});


//verification on registering 
app.get('/verify', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'verify.html'));
})


app.post('/verification', async (req, res) => {
    const { email, token } = req.body;
    try {
        const user = await User.findOne({ email, verificationToken: token });
        if (!user || user.verificationExpiry < Date.now()) {
            return res.status(400).json({ message: "Invalid or expired link" })
        }

        user.verified = true;
        user.verificationToken = undefined;
        user.verificationExpiry = undefined;
        user.verificationAttempts = undefined
        await user.save();
        return res.status(200).json({ message: 'User verified successfully' });
    } catch (error) {
        return res.status(500).json({ message: 'Error verifying user' });
    }
})




app.post('/isverifieduser', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    if (user.verified === false) {
        return res.status(200).json({ verified: false });
    }

    return res.status(200).json({ verified: true });
});


app.post('/resendMail', async (req, res) => {
    const { email } = req.body;
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationExpiry = Date.now() + 3600000; // 1 hour expiry

    const verifyLink = `https://basic-auth-app-six.vercel.app/verify?email=${email}&token=${verificationToken}`;
    const htmlContent = `
        <html>
        <body>
            <h1>Welcome to Our Service</h1>
            <p>Hello,</p>
            <p>Click the link below to verify your account:</p>
            <a href="${verifyLink}" target="_blank">Verify Account</a>
        </body>
        </html>
    `;

    const mailOptions = {
        from: 'no@reply.com',  // Replace with your sender email
        to: email,
        subject: 'Verification email',
        html: htmlContent
    };

    const user = await User.findOne({ email });
    if (user) {
        user.verificationToken = verificationToken;   // Update verify token
        user.verificationExpiry = verificationExpiry;       // Update expiry

        // Increment verification attempts (optional)
        user.verificationAttempts += 1;

        // Save the updated user data to the database
        await user.save();

        // Send the email
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(500).json({ message: "Failed to send email" });
            }
            return res.status(200).json({ message: "Verification email sent successfully!" });
        });
    } else {
        // If the user is not found, handle the error
        return res.status(404).send({ message: 'User not found' });
    }
})

app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', '/notfound.html'));  // Serve custom 404 page from 'static' folder
});

// Other routes...

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
