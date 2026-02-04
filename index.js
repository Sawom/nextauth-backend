require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { MongoClient } = require("mongodb");
const jwt = require("jsonwebtoken");
const { Resend } = require('resend');
const crypto = require('crypto');
const nodemailer = require("nodemailer");

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

const resend = new Resend(process.env.RESEND_KEY);

// MongoDB Connection URL
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// create nodemailer transporter 
const transporter = nodemailer.createTransport({
  service: "gmail",
  host: "smtp.gmail.com",
  port: 465,
  secure: true, 
  auth: {
    user: process.env.EMAIL, 
    pass: process.env.APP_PASS,
  },
});


async function run() {
  try {
    // Connect to MongoDB
    await client.connect();
    console.log("Connected to MongoDB");

    // database name and collection name
    const db = client.db("nextAuth");
    const collection = db.collection("users");

    // create user: User Registration and also handled social login like google, github
    app.post("/api/v1/register", async (req, res) => {
      try{
        const{username, email, password, provider} = req.body;
        const currentTime = new Date();
        // check if user existing
        const existingUser = await collection.findOne({ email });

        if(existingUser){
          await collection.updateOne(
            {email},
            {$set: {lastLogin: currentTime}}
          )
          return res.status(200).json({
            success: true,
            message: "User logged in successfully!",
            user: { ...existingUser, lastLogin: currentTime },
          });
        }

        // if password then password will be hashed. not for social login features
        let hashedPassword = null;
          if (password) {
            hashedPassword = await bcrypt.hash(password, 10);
        }

        // for new user
        const newUser = {
          username: username || email.split("@")[0],
          email,
          password: hashedPassword,
          role: "user",
          provider: provider || "credentials",
          createdAt: currentTime,
          lastLogin: currentTime,
        };

        await collection.insertOne(newUser);

        res.status(201).json({
          success: true,
          message: "User registered successfully!",
          user: newUser
        });

      }

      catch(error){
          res.status(500).json({
            success: false,
            message: "Something went wrong"
          })
      }

    });

    // User Login
    app.post("/api/v1/login", async (req, res) => {
      try{
        const { email, password } = req.body;

        // Find user by email
        const user = await collection.findOne({ email });
        if (!user || !user.password) {
          console.log("User not found in DB");
          return res.status(401).json({ message: "Invalid email or password" });
        }

        // Compare hashed password
        const isPasswordValid = await bcrypt.compare(password.trim(), user.password);
        console.log("Comparison Result:", isPasswordValid);
        if (!isPasswordValid) {
          return res.status(401).json({ message: "Invalid email or password" });
        }

        // time data taken when user enter the site
        const currentTime = new Date();
        await collection.updateOne(
          {email: email},
          { $set: {lastLogin: currentTime} }
        );

        // Generate JWT token
        const token = jwt.sign(
          { email: user.email, role: user.role },
          process.env.JWT_SECRET,
          {
            expiresIn: process.env.EXPIRES_IN,
          }
        );

        res.json({
          success: true,
          message: "User successfully logged in!",
          accessToken: token,
          lastLogin: currentTime
        });

      }

      catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "Internal server error" });
      }

    });


    // forget password and send email api
    app.post("/api/auth/forgot-password", async(req, res)=>{
      const {email} = req.body;
      // 1st check in database if user exist
      const userExists = await collection.findOne({ email });
      if(!userExists) {
        return res.status(404).json({ message: "User not found" });
      }

      try{
        await transporter.sendMail({
          from: '"My Custom App" <asawom250@gmail.com>', 
          to: email, // user email from frontend
          subject: "Password Reset Request", 
          html: `
            <div style="font-family: Arial, sans-serif; padding: 20px;">
              <h2>Reset Password</h2>
              <p> You are requested to reset your password. Click the link below: </p>
              <a href="${resetLink}" style="background: #000; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a>
              <p>this link is worked for 10 minutes </p>
            </div>
          `,
        });
        res.status(200).json({success: true, message: "Email sent successfully!"})

      }catch (error) {
        console.log(error);
        res.status(500).json({ success: false, message: "Failed to send email" });
      }

    } )

    

    
    // Start the server
    app.listen(port, () => {
      console.log(`Server is running on http://localhost:${port}`);
    });
  } finally {

  }
}

run().catch(console.dir);

// Test route
app.get("/", (req, res) => {
  const serverStatus = {
    message: "Server is running for next auth server",
    timestamp: new Date(),
  };
  res.json(serverStatus);
});
