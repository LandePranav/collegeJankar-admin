const express = require('express');
const bcrypt = require('bcrypt');
const Seller = require('../models/seller'); // Adjust the path to your Seller schema
const router = express.Router();
const crypto = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();
const checkRole = require("../middleware/checkRole");

const generateVerificationToken = () => {
  return crypto.randomBytes(32).toString('hex');
}

const transporter = nodemailer.createTransport({
  service: 'gmail', // Use your email service (e.g., Gmail, SendGrid)
  auth: {
    user: process.env.EMAIL_USER, // Replace with your email
    pass: process.env.EMAIL_PASS, // Replace with your email password
  },
});

const sendVerificationEmail = async (email,sellerId, verificationToken) => {
  const verificationLink = `http://localhost:5000/admin/verify-email?token=${verificationToken}`;
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Verify Your Email",
    html: `
    <div>
      <h2>Welcome Aboard Seller </h2>
      <h3>User Your New Unique Id to Login, but first verify</h3>
      <h3>Unique ID : ${sellerId} </h3>
      <p>Please click the link below to verify your email:</p>

      <a href="${verificationLink}">Verify Email with link ${verificationLink}</a>
      </div>
    `
  };
  try {
    await transporter.sendMail(mailOptions);
    console.log('Verification email sent!');
  } catch (error) {
    console.error("Error sending verification Email: ", error)
  }
}

// Seller Login
router.post('/login', async (req, res) => {
  try {
    const { sellerId, emailOrPhone, password } = req.body;

    // Validate required fields
    if (!sellerId || !emailOrPhone || !password) {
      return res.status(400).json({
        error: 'Missing required fields',
        details: 'Seller ID, email/phone, and password are required'
      });
    }

    // Find seller by ID and email/phone
    const seller = await Seller.findOne({
      sellerId,
      $or: [
        { email: emailOrPhone },
        { phoneNumber: emailOrPhone }
      ]
    });

    if (!seller) {
      return res.status(400).json({
        error: 'Invalid credentials',
        details: 'No seller found with provided ID and email/phone'
      });
    }

    // Check if email/phone is verified
    if (!seller.emailVerified && !seller.phoneVerified) {
      return res.status(401).json({
        error: 'Account not verified',
        details: 'Please verify your email or phone number before logging in'
      });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, seller.password);
    if (!isMatch) {
      return res.status(400).json({
        error: 'Invalid credentials',
        details: 'Incorrect password provided'
      });
    }
    // Update loggedIn status
    seller.loggedIn = 'loggedin';
    await seller.save();
    // Store sellerId in session
    req.session.sellerId = sellerId;
    req.session.role = seller.role;
    res.status(200).json({
      success: true,
      message: 'Login successful',
      sellerId,
      role: seller.role
    });
  } catch (error) {
    res.status(500).json({
      error: 'Error logging in',
      details: error.message
    });
  }
});

// Seller Signup
router.post('/seller/signup', async (req, res) => {
  try {
    const  {phoneNumber, emailId, password } = req.body;

    // Check if seller already exists
    const existingSeller = await Seller.findOne({ email: emailId });
    if (existingSeller) {
      return res.status(400).json({ error: 'Seller already exists' });
    }

    // Generate unique seller ID (MBSLR + 5 digits)
    let sellerId;
    let isUnique = false;
    while (!isUnique) {
      const randomNum = Math.floor(10000 + Math.random() * 90000);
      sellerId = `MBSLR${randomNum}`;
      const existingId = await Seller.findOne({ sellerId });
      if (!existingId) isUnique = true;
    }

    //generate verify token
    const verificationToken = generateVerificationToken();
    const verificationTokenExpiry = Date.now() + 3600000; //1hr expiry

    // Create new seller with required fields from schema
    const seller = new Seller({
      name: 'Not Available',
      email: emailId,
      password: password,
      sellerId: sellerId,
      emailVerified: false,
      phoneVerified: false,
      phoneNumber: phoneNumber,
      businessName: 'Not Available',
      businessAddress: 'Not Available',
      businessType: 'Not Available',
      verificationToken,
      verificationTokenExpiry
    });

    await seller.save();

    // Store sellerId in session
    req.session.sellerId = sellerId;
    await sendVerificationEmail(emailId,sellerId, verificationToken);

    res.status(201).json({
      message: 'Seller registered successfully. Please check mail to verify account',
      sellerId
    });
  } catch (err) {
    res.status(500).json({
      error: 'Error registering seller',
      message: err.message
    });
  }
});

router.post('/verify-seller', async (req, res) => {
  try {
    const { sellerId } = req.body;

    if (!sellerId) {
      return res.status(400).json({
        success: false,
        message: 'Seller ID is required'
      });
    }

    // Find seller by sellerId
    const seller = await Seller.findOne({ sellerId });

    if (!seller) {
      return res.status(404).json({
        success: false,
        message: 'Invalid seller ID'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Valid seller ID',
      loggedIn: seller.loggedIn
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error verifying seller ID',
      error: error.message
    });
  }
});

router.get('/verify-email', async (req,res) => {
  const {token} = req.query;

  try {
    // Find the seller by the verification token
    const seller = await Seller.findOne({ verificationToken: token });

    if (!seller) {
      return res.status(400).json({ message: 'Invalid verification token' });
    }

    // Check if the token has expired
    if (seller.verificationTokenExpiry < Date.now()) {
      return res.status(400).json({ message: 'Verification token has expired' });
    }

    // Mark the seller as verified
    seller.emailVerified = true;
    seller.verificationToken = undefined;
    seller.verificationTokenExpiry = undefined;
    await seller.save();

    res.status(200).json({ message: 'Email verified successfully' });
  } catch (error) {
    console.error('Error verifying email:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
})

router.post('/resend-verification-email', async (req,res) => {
  const {email} = req.body;

  try {

    const seller = await Seller.findOne({ email });

    if (!seller) {
      return res.status(404).json({ message: 'Seller not found' });
    }

    if (seller.emailVerified) {
      return res.status(400).json({ message: 'Email is already verified' });
    }

    // Generate a new verification token
    const verificationToken = generateVerificationToken();
    const verificationTokenExpiry = Date.now() + 3600000; // 1 hour

    seller.verificationToken = verificationToken;
    seller.verificationTokenExpiry = verificationTokenExpiry;
    await seller.save();

    // Send the verification email
    await sendVerificationEmail(email,seller.sellerId, verificationToken);

    res.status(200).json({ message: 'Verification email sent' });
    
  } catch (error) {
    console.error("Error resending verification email: ", error);
    res.status(500).json({message: 'Internal server error'});
  }
})

router.post('/logout', async (req, res) => {
  try {
    const { sellerId } = req.body;

    if (!sellerId) {
      return res.status(400).json({
        error: 'Seller ID is required'
      });
    }

    const seller = await Seller.findOne({ sellerId });
    
    if (!seller) {
      return res.status(404).json({
        error: 'Seller not found'
      });
    }

    seller.loggedIn = 'loggedout';
    await seller.save();

    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: 'Error logging out' });
      }
      res.clearCookie('connect.sid');
      res.json({ 
        success: true,
        message: 'Seller logged out successfully',
        loggedIn: 'loggedout'
      });
    });

  } catch (error) {
    res.status(500).json({
      error: 'Error logging out',
      details: error.message
    });
  }
});

module.exports = router;
