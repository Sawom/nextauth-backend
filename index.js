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

// here I get *APP_PASS* from .env,
// when you visit .env file you can see a *APP_PASS* value. That value is come from google account.
// to get it, go to your google account profile > Security then search *App password*. then google
// ask you to login and after that you should create an app and after enter you get the *app password *
// which is saved as *APP_PASS*

async function run() {
  try {
    // Connect to MongoDB
    await client.connect();
    console.log("Connected to MongoDB");

    // database name and collection name
    const db = client.db("nextAuth");
    const collection = db.collection("users"); // for users
    const resetEntry = db.collection("password_resets") // for reset password

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
    app.post("/api/v1/forgot-password", async(req, res)=>{
      const {email} = req.body;
      // 1. check in database if user exist
      const userExists = await collection.findOne({ email });
      if(!userExists) {
        return res.status(404).json({ message: "User not found" });
      }

      // 2.  unique token generate
      const resetToken = crypto.randomBytes(32).toString('hex');
      
      // 3. token save in database with 10mins expire time
      const tokenExpiry = new Date(Date.now() + 10*60*1000 );
      
      // 4. token saved in database in another collection for 10 minutes
      await resetEntry.updateOne(
        {
          email: email
        },
        { 
          $set: { 
            email: email, 
            token: resetToken, 
            expiresAt: tokenExpiry
          } 
        },
        { upsert: true }
      )
      
      // 5. create reset password link
      const resetLink = `http://localhost:3000/api/v1/reset-password?token=${resetToken}`;

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

    /**
 * =============================================================
 * PASSWORD RESET PROCESS (STEP-BY-STEP)
 * =============================================================
 * * STEP 1: User Input
 * - User tar email address "/forget-password" page-e dibe.
 * * STEP 2: Database Check
 * - Check korbo ai email-e kono account database-e ache ki na.
 * - Na thakle 404 Error (User Not Found) dibo.
 * * STEP 3: Generate Secure Token (Crypto)
 * - 'crypto' module diye ekta 64 characters-er random hex string (Token) banabo.
 * - Eta security-r jnno dorkar jate keu guess na korte pare.
 * * STEP 4: Set Expiration Time (10 Minutes)
 * - Bortoman shomoyer (Date.now()) sathe 10 minute (10*60*1000 ms) jog korbo.
 * - Ai 'Expiry Time' ar 'Token' ta Database-e user-er email-er sathe save korbo.
 * * STEP 5: Create Reset Link
 * - Ekta URL banabo jemon: http://localhost:3000/reset-password?token=XYZ...
 * - Eikhane 'token' query parameter hishebe thakbe.
 * * STEP 6: Send Email (Nodemailer)
 * - Ai Link ta user-er email-e HTML button ba link hishebe pathabo.
 * * STEP 7: User Click & Redirect
 * - User email-er link-e click korle se Next.js-er "/reset-password" page-e jabe.
 * - URL theke 'token' ta niye backend-e pathabe password change korar shomoy.
 * * STEP 8: Final Verification (Backend)
 * - Backend check korbe: 
 * a) Token ta database-e ache ki na.
 * b) Token er expiry time shesh hoye geche ki na.
 * - Sob thik thakle database-e user-er password update hobe.
 * =============================================================
 */
 
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
