// routes/authRoutes.js
const express = require("express");
const {
  register,
  login,
  verifyEmail,
  requestPasswordReset,
  resetPassword,
} = require("../controllers/authController");
const protect = require("../middleware/authMiddleware");

const router = express.Router();

router.post("/register", register); // Registration route
router.post("/login", login); // Login route
router.get("/verify-email", verifyEmail); // Email verification route
router.post("/request-password-reset", requestPasswordReset); // Request password reset
router.post("/reset-password", resetPassword); // Reset password
router.get("/protected", protect, (req, res) => {
  res.status(200).json({ message: "Protected route accessed", user: req.user });
});

module.exports = router;
