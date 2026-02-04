require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { MongoClient } = require("mongodb");
const jwt = require("jsonwebtoken");
const crypto = require('crypto');
const nodemailer = require("nodemailer");

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

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
    // console.log("Connected to MongoDB");

    // database name and collection name
    const db = client.db("nextAuth");
    const collection = db.collection("users"); // for users
    const resetEntry = db.collection("password_resets"); // for reset password
    
    // create a index for automatically token delete after 10 mins
    // this function set index for token delete after 10 mins
    const setupIndices = async () => {
      try {
        await resetEntry.createIndex({ "expiresAt": 1 }, { expireAfterSeconds: 0 });
        // console.log("TTL Index created successfully.");
      } catch (error) {
        console.error("Error creating index:", error);
      }
    };
    setupIndices(); // this is called when server starts

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
          // console.log("User not found in DB");
          return res.status(401).json({ message: "Invalid email or password" });
        }

        // Compare hashed password
        const isPasswordValid = await bcrypt.compare(password.trim(), user.password);
        // console.log("Comparison Result:", isPasswordValid);
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
      const resetLink = `http://localhost:3000/reset-password?token=${resetToken}`;

      try{
        await transporter.sendMail({
          from: '" user management App" <asawom250@gmail.com>', // change your app name if you want
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

      }
      catch (error) {
        // console.log(error);
        res.status(500).json({ success: false, message: "Failed to send email" });
      }

    } )

    // update password
    app.post("/api/v1/update-password", async(req, res)=>{
      // 1. cleaning token if space exist
      const { token, newPassword } = req.body;
      const cleanToken = token ? token.trim() : "";
      // console.log("Postman token:", cleanToken);
      
      try{
          // 2. check if token in collection and if token in validate time
          const resetData = await resetEntry.findOne({ token: cleanToken });
          // console.log("Database data:", resetData);
          
          if (!resetData) {
            return res.status(400).json({ success: false, message: "Invalid or Expired Token!" });
          }

          // 3. check time and confirm date object
          const expiryTime = new Date(resetData.expiresAt);
          if (new Date() > expiryTime) {
            await resetEntry.deleteOne({ token: cleanToken });
            return res.status(400).json({ success: false, message: "Link has expired!" });
          }

          // 4. new password hash
          const hashedNewPassword = await bcrypt.hash(newPassword, 10);

          // 5. main user's password update and put in result variable
          const updateResult = await collection.updateOne(
            { email: resetData.email },
            { $set: { password: hashedNewPassword } }
          );

          // check if password is updated
          if (updateResult.modifiedCount === 0) {
            return res.status(404).json({ success: false, message: "User not found!" });
          }

          // 6. token delete after password changed
          await resetEntry.deleteOne({ token: cleanToken })
          res.status(200).json({ success: true, message: "Password updated successfully!" });
        }

        catch (error) {
          // console.log(error);
          res.status(500).json({ success: false, message: "Something went wrong!" });
        }
    } )

    /**
   * API to check if the reset token is still valid and 
   * calculate the remaining time for the countdown timer.
   */
    app.get("/api/v1/reset-token-status/:token", async (req, res) => {
      const { token } = req.params;
      try {
        // 1. Check if the token exists in the database
        const resetData = await resetEntry.findOne({ token });

        if (!resetData) {
          return res.status(404).json({ success: false, message: "Token not found" });
        }

        // 2. Calculate the difference between Expiry Time and Current Time
        const now = new Date();
        const expiry = new Date(resetData.expiresAt);
        // Difference is in milliseconds, so we divide by 1000 to get seconds
        const timeLeftInSeconds = Math.floor((expiry - now) / 1000);

        // 3. If time has run out, let the frontend know immediately
        if (timeLeftInSeconds <= 0) {
          return res.status(400).json({ 
            success: false, 
            message: "Token already expired", 
            timeLeft: 0 
          });
        }
      // 4. Return the exact remaining seconds to sync the frontend timer
        res.status(200).json({ success: true, timeLeft: timeLeftInSeconds });
      } catch (error) {
        res.status(500).json({ success: false, message: "Server error" });
      }
    });

    /**
 * =============================================================
 * PASSWORD RESET PROCESS (STEP-BY-STEP)
 * =============================================================
 * * STEP 1: User Input
 * - The user enters their registered email address on the "/forgot-password" page.
 * * STEP 2: Database Check
 * - Verify if the email exists in the database.
 * - If not found, return a 404 Error (User Not Found).
 * * STEP 3: Generate Secure Token (Crypto)
 * - Create a secure, 64-character random hex string using the 'crypto' module.
 * - This ensures the token is unique and impossible to guess.
 * * STEP 4: Set Expiration Time (10 Minutes)
 * - Calculate expiry time by adding 10 minutes (10 * 60 * 1000 ms) to the current time.
 * - Save the 'token', 'email', and 'expiresAt' in the database (password_resets collection).
 * * STEP 5: Create Reset Link
 * - Generate a unique URL, for example: http://localhost:3000/reset-password?token=XYZ...
 * - The token is passed as a query parameter in the URL.
 * * STEP 6: Send Email (Nodemailer)
 * - Send the reset link to the user's email as a clickable button or link using Nodemailer.
 * * STEP 7: User Redirection
 * - Clicking the link takes the user to the Next.js "/reset-password" page.
 * - The frontend extracts the 'token' from the URL to send it back to the server.
 * * STEP 8: Final Verification & Update (Backend)
 * - The backend validates the request by checking:
 * a) If the token exists in the database.
 * b) If the token is still within the 10-minute expiry window.
 * - Once verified, the user's password is hashed and updated in the main collection.
 * - Finally, the reset token is deleted from the database for security.
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
