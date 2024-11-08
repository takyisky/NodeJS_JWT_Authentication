// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Define the User schema
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
    minlength: 6, // Add password length validation
  },
  isVerified: {
    type: Boolean,
    default: false, // Initial value set to false until email is verified
  },
});

// Password hashing before saving to database
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  // Generate salt and hash password
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Method to compare entered password with hashed password
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Compile and export the User model
module.exports = mongoose.model('User', userSchema);
