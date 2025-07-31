// server.js
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const app = express();
const port = process.env.PORT || 3000;

const userDB = new Map(); // In-memory store, use real DB in production

app.use(cors({
  origin: "https://atsh.tech", // ✅ Replace with your frontend domain
  credentials: true,
}));
app.use(bodyParser.json());

// 🔹 REGISTER - Step 1: Get registration options
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
    rpID: "atsh.tech", // ✅ Your domain
    user,
    timeout: 60000,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "discouraged",
      userVerification: "preferred",
    },
  });

  userDB.set(email, {
    ...user,
    currentChallenge: options.challenge,
  });

  res.json(options);
});

// 🔹 REGISTER - Step 2: Verify registration
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
      expectedOrigin: "https://atsh.tech",
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


// 🔸 LOGIN - Step 1: Get authentication options
app.post("/login/options", async (req, res) => {
  const { email } = req.body;
  const user = userDB.get(email);

  if (!user || !user.credential) {
    return res.status(400).json({ error: "No credential registered" });
  }

  const options = generateAuthenticationOptions({
    timeout: 60000,
    allowCredentials: [{
      id: Buffer.from(user.credential.credentialID.data),
      type: 'public-key',
      transports: ['internal'],
    }],
    userVerification: 'preferred',
    rpID: "atsh.tech",
  });

  user.currentChallenge = options.challenge;
  userDB.set(email, user);

  res.json(options);
});


// 🔸 LOGIN - Step 2: Verify authentication
app.post("/login/verify", async (req, res) => {
  const { email, authResp } = req.body;
  const user = userDB.get(email);

  if (!user || !user.credential) {
    return res.status(400).json({ error: "No credential found" });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: authResp,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: "https://atsh.tech",
      expectedRPID: "atsh.tech",
      authenticator: {
        credentialID: Buffer.from(user.credential.credentialID.data),
        credentialPublicKey: Buffer.from(user.credential.credentialPublicKey.data),
        counter: user.credential.counter || 0,
      },
    });

    if (verification.verified) {
      user.credential.counter = verification.authenticationInfo.newCounter;
      userDB.set(email, user);
    }

    res.json({ verified: verification.verified });
  } catch (err) {
    console.error("Auth verification failed:", err);
    res.status(500).json({ error: "Authentication failed" });
  }
});


app.listen(port, () => {
  console.log(`✅ Server running at http://localhost:${port}`);
});
