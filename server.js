// server.js
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} = require("@simplewebauthn/server");

const app = express();
const port = process.env.PORT || 3000;

const userDB = new Map(); // temp DB — replace with real DB if needed

app.use(cors({
  origin: "https://atsh.tech", // ✅ Your Netlify custom domain
  credentials: true,
}));
app.use(bodyParser.json());

// 🔹 Step 1: Registration options
app.post("/register/options", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Missing email" });

  const user = {
    id: Buffer.from(email).toString("base64"),
    name: email,
    displayName: email,
  };

  const options = generateRegistrationOptions({
    rpName: "Ascandane",
    rpID: "atsh.tech", // ✅ your domain
    user,
    timeout: 60000,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "discouraged",
      userVerification: "preferred",
    },
  });

  // Save challenge temporarily
  userDB.set(email, {
    ...user,
    currentChallenge: options.challenge,
  });

  res.json(options);
});

// 🔹 Step 2: Verify registration response
app.post("/register/verify", async (req, res) => {
  const { email, attResp } = req.body;
  const user = userDB.get(email);

  if (!user || !user.currentChallenge) {
    return res.status(400).json({ error: "Invalid user or challenge" });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: attResp,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: "https://atsh.tech", // ✅ Your site on Netlify
      expectedRPID: "atsh.tech",
    });

    if (verification.verified) {
      user.credential = verification.registrationInfo;
      userDB.set(email, user);
    }

    res.json({ verified: verification.verified });
  } catch (err) {
    console.error("Verification error:", err);
    res.status(500).json({ error: "Verification failed" });
  }
});

app.listen(port, () => {
  console.log(`✅ Server running at http://localhost:${port}`);
});
