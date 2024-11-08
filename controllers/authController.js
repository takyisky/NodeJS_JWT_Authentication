// controllers/authController.js
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/Users");
require("dotenv").config();

// Helper function to generate a JWT token for verification
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

const nodemailer = require("nodemailer");

// Set up Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: "gmail", // or another SMTP provider
  auth: {
    user: process.env.EMAIL_USER, // e.g., your Gmail account
    pass: process.env.EMAIL_PASS, // app password for Gmail or API key for other services
  },
});

// Helper function to send a verification email using EmailJS
const sendVerificationEmail = async (user) => {
  const token = generateToken(user._id);
  const verificationLink = `http://localhost:5000/api/auth/verify-email?token=${token}`;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: user.email,
    subject: "Email Verification",
    html: `<p>Click <a href="${verificationLink}">here</a> to verify your email.</p>`,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log("Verification email sent:", info.response);
  } catch (error) {
    console.error("Failed to send verification email:", error);
  }
};

// Register new user
exports.register = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if the user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

    // Create the new user
    const user = new User({ email, password });
    await user.save();

    // Send verification email
    await sendVerificationEmail(user);

    res.status(201).json({
      message:
        "Registration successful. Please check your email to verify your account.",
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
};

// Login user
exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    // Check if the password matches
    const isMatch = await user.matchPassword(password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });

    // Generate JWT token
    const token = generateToken(user._id);

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
};

// Verify email using token
exports.verifyEmail = async (req, res) => {
  const { token } = req.query;

  try {
    // Decode and verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Find user by decoded ID
    const user = await User.findById(decoded.id);

    if (!user)
      return res
        .status(400)
        .json({ message: "Invalid token or user not found" });
    if (user.isVerified)
      return res.status(400).json({ message: "Email is already verified" });

    // Update user's verification status
    user.isVerified = true;
    await user.save();

    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    res.status(500).json({ message: "Invalid or expired token", error });
  }
};
