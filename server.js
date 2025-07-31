const express = require('express');
const cors = require('cors');
const base64url = require('base64url');
const { generateRegistrationOptions, verifyRegistrationResponse } = require('@simplewebauthn/server');

const app = express();
app.use(cors());
app.use(express.json());

// In-memory DB (use real DB in production)
const db = {
  users: {},
};

app.post('/register/options', (req, res) => {
  const { email } = req.body;
  const userId = email;

  const user = db.users[email] || {
    id: base64url.encode(Buffer.from(email)),
    email,
    credentials: [],
  };

  const options = generateRegistrationOptions({
    rpName: 'Ascandane',
    rpID: 'your-domain.netlify.app', // Replace this
    userID: user.id,
    userName: user.email,
    attestationType: 'indirect',
    authenticatorSelection: {
      userVerification: 'preferred',
      residentKey: 'required',
    },
  });

  user.currentChallenge = options.challenge;
  db.users[email] = user;

  res.json(options);
});

app.post('/register/verify', async (req, res) => {
  const { email, attResp } = req.body;
  const user = db.users[email];
  if (!user) return res.status(400).json({ verified: false });

  try {
    const verification = await verifyRegistrationResponse({
      response: attResp,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: 'https://your-domain.netlify.app', // Replace with your Netlify URL
      expectedRPID: 'your-domain.netlify.app',
    });

    if (verification.verified) {
      user.credentials.push(verification.registrationInfo);
      return res.json({ verified: true });
    }

    res.json({ verified: false });
  } catch (err) {
    console.error(err);
    res.json({ verified: false });
  }
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
