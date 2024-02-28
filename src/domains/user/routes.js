require('dotenv').config();

const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const User = require('./model');
const jwt = require("jsonwebtoken");
const generateUsername = require('../../utils/names');




// Get all users endpoint
router.get('/', async (req, res) => {
  try {
    // Fetch all users from the database, excluding password and airdropReceived
    const users = await User.find({}, { password: 0, airdropReceived: 0, transactions: 0});

    // Respond with the users
    res.status(200).json(users);
  } catch (error) {
    // Handle errors
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Signup endpoint
router.post('/register', async (req, res) => {
  try {
    // Extract user data from request body
    const { userName, password } = req.body;

    // Generate unique codeName
    const codeName = await generateUsername(); 

    // Check if user already exists
    const existingUser = await User.findOne({ userName });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({
      userName,
      codeName,
      password: hashedPassword
    });

    // Save the user to the database
    await newUser.save();


    // Respond with success message
    res.status(201).json({ 
      message: 'User created successfully',
      codeName: newUser.codeName,
     });
  } catch (error) {
    // Handle errors
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Signup endpoint2
// router.post('/register', async (req, res) => {
//   try {
//     // Extract user data from request body
//     const { userName, password } = req.body;

//     // Validation
//     if (!userName || !password) {
//       return res.status(400).json({ message: 'Username and password are required' });
//     }

//     // Check username format
//     const userNameRegex = /^[a-zA-Z0-9]+$/;
//     if (!userNameRegex.test(userName)) {
//       return res.status(400).json({ message: 'Invalid username format. Username can only contain letters and numbers.' });
//     }

//     // Check password length
//     if (password.length < 8) {
//       return res.status(400).json({ message: 'Password must be at least 8 characters long' });
//     }

//     // Generate unique codeName
//     const codeName = await generateUsername(); 

//     // Check if user already exists
//     const existingUser = await User.findOne({ userName });
//     if (existingUser) {
//       return res.status(400).json({ message: 'User already exists' });
//     }

//     // Hash the password
//     const hashedPassword = await bcrypt.hash(password, 10);

//     // Create new user
//     const newUser = new User({
//       userName,
//       codeName,
//       password: hashedPassword
//     });

//     // Save the user to the database
//     await newUser.save();

//     // Respond with success message
//     res.status(201).json({ 
//       message: 'User created successfully',
//       codeName: newUser.codeName,
//     });
//   } catch (error) {
//     // Handle errors
//     console.error(error);
//     res.status(500).json({ message: 'Internal server error' });
//   }
// });


// Login endpoint
router.post('/login', async (req, res) => {
  try {
    // Extract user data from request body
    const { userName, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ userName });
    if (!user) {
      return res.status(401).json({ message: 'Invalid username' });
    }

    // Compare passwords
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    // Authentication successful
    // Generate access token with only user id and username in the payload
    const maxAge = 3 * 24 * 60 * 60;
    const accessToken = jwt.sign({ userId: user._id, userName: user.userName }, process.env.JWT_SECRET, {
      expiresIn: maxAge
    });
    res.cookie('jwt', accessToken, { 
      httpOnly: true, 
      maxAge: maxAge * 1000, 
      secure: true, 
      sameSite: 'none'
    });
    res.status(200).json({ 
      message: 'Login successful',
      token: accessToken,
      user: user,
      userId: user._id, 
      userName: user.userName,
    });
    console.log('User logged in:', user.userName);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Define a route to get a fully populated user object
// Define the getUser route
router.get('/getUser', async (req, res) => {
  try {
    // Extract JWT token from the cookies
    const token = req.cookies.jwt;

    // Verify and decode the JWT token
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decodedToken.userId;

    // Fetch user data from the database using the decoded user ID
    const user = await User.findById(userId);

    // Check if the user exists
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Respond with the fully populated user object
    res.status(200).json({ user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

  
// Logout endpoint
router.get('/logout', (req, res) => {
  try {
    // Clear the JWT cookie
    res.clearCookie('jwt');

    // Respond with success message
    res.status(200).json({ message: 'Logout successful' });

    // Log user logout
    console.log('User logged out');
  } catch (error) {
    // Handle errors
    console.error('Error occurred during logout:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});




// Get user by ID endpoint
router.get('/:id', async (req, res) => {
  try {
    // Extract user ID from request parameters
    const { id } = req.params;

    // Fetch user from the database
    const user = await User.findById(id);

    // Respond with the user
    res.status(200).json(user);
  } catch (error) {
    // Handle errors
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
   
// GET endpoint to fetch user data
router.get('/getUser', async (req, res) => {
  try {
    // Extract user ID from request parameters
    const { userId } = req.params;

    // Fetch user from the database
    const user = await User.findById(userId, { password: 0, airdropReceived: 0, transactions: 0});

    // Respond with the user
    res.status(200).json(user);
  } catch (error) {
    // Handle errors
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});





module.exports = router;
