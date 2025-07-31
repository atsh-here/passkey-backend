const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} = require("@simplewebauthn/server");

const app = express();
const port = process.env.PORT || 3000;

// In-memory user store (use a real DB in production)
const userDB = new Map();

app.use(cors({
  origin: "https://atsh.tech", // Allow requests only from your Netlify domain
  credentials: true
}));
app.use(bodyParser.json());

// 1. Generate registration options
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
    rpID: "atsh.tech",                     // Custom domain as RP ID
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

// 2. Verify registration response
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
      expectedOrigin: "https://atsh.tech",   // 
      expectedRPID: "atsh.tech",             // 
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
  console.log(`🚀 Server running on http://localhost:${port}`);
});
