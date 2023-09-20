const express = require("express");
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const ipinfo = require("ipinfo");
const twilio = require("twilio");

const accountSid = "AC3fd976b505297a719d8fd1eb7422e1b9";
const authToken = "9561d5880f459db672137be5f7100acf";

const app = express();
app.use(express.json());
const dbPath = path.join(__dirname, "userregistrationsystem.db");

let db = null;

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(3000, () => {
      console.log("Server Running at http://localhost:3000/");
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};
const otpStore = {};
initializeDBAndServer();

// USER REGISTRATION API
app.post("/user/", async (request, response) => {
  const { ip_address, mobileNumber } = request.body;

  if (!ip_address) {
    console.error("Empty IP address.");
    return response.status(400).json({ error: "Empty IP address" });
  }

  const client = new twilio(accountSid, authToken);

  try {
    const data = await ipinfo(ip_address);
    if (data.ip) {
      const otp = Math.floor(1000 + Math.random() * 9000); // Generate a 4-digit OTP
      const userPhoneNumber = mobileNumber;
      otpStore[userPhoneNumber] = otp;

      const hashedOTP = await bcrypt.hash(otp.toString(), 10);

      try {
        await db.run(
          "INSERT INTO user (mobileNumber, otpStore) VALUES (?, ?)",
          [userPhoneNumber, hashedOTP]
        );
      } catch (err) {
        console.error(`Error inserting user into the database: ${err}`);
        response.status(500).json({ error: "Internal server error" });
        return;
      }

      client.messages
        .create({
          body: `Your OTP is: ${otp}`,
          from: "+14789998024",
          to: userPhoneNumber,
        })
        .then((message) => {
          console.log(`OTP sent with SID: ${message.sid}`);
        })
        .catch((error) => {
          console.error(`Error sending OTP: ${error}`);
        });
      response.status(200).json({ otp: otp });
    } else {
      console.error(`${ip_address} is not a valid IP address.`);
      response.status(400).json({ error: "Invalid IP address" });
    }
  } catch (err) {
    response.status(500).json({ error: `Internal server error ${err}` });
  }
});

// Validate OTP and Register User

app.post("/user/validateOTP/", async (request, response) => {
  const { userPhoneNumber, enteredOTP, ip_address } = request.body;

  try {
    // Retrieve the stored OTP from the database
    const query = `SELECT 
      otpStore 
    FROM 
      user 
    WHERE 
      mobileNumber = ? 
    ORDER BY 
      id 
    DESC LIMIT 1;`;
    const row = await db.get(query, [userPhoneNumber]);

    if (!row) {
      // The user's phone number was not found in the database
      return response.status(404).json({ error: "User not found" });
    }
    const storedHashedOTP = row.otpStore;

    // Compare the entered OTP with the stored hashed OTP
    const isOTPValid = await bcrypt.compare(enteredOTP, storedHashedOTP);

    const storedOTP = String(row.otpStore);
    console.log(storedOTP);
    console.log(enteredOTP);

    if (isOTPValid) {
      // The entered OTP matches the stored OTP, so it's valid
      // Now, you can add the user to the database if OTP matches
      const addUserQuery = `
        INSERT INTO userRegistration (mobileNumber, ip_address)
        VALUES (?, ?)
      `;
      try {
        await db.run(addUserQuery, [userPhoneNumber, ip_address]);
        return response
          .status(200)
          .json({ message: "OTP is valid and user registered successfully" });
      } catch (err) {
        console.error(`Error inserting user into the database: ${err}`);
        return response.status(500).json({ error: "Internal server error" });
      }

      return response.status(200).json({ message: "OTP is valid" });
    } else {
      // The entered OTP does not match the stored OTP, so it's invalid
      return response.status(400).json({ error: "Invalid OTP" });
    }
  } catch (err) {
    console.error(`Error querying the database: ${err}`);
    return response.status(500).json({ error: "Internal server error" });
  }
});
