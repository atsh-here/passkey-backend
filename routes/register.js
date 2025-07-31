const express = require('express');
const { generateRegistrationOptions, verifyRegistrationResponse } = require('@simplewebauthn/server');
const base64url = require('base64url');
const { saveUser, getUser } = require('../utils/users');

const router = express.Router();

router.post('/options', (req, res) => {
  const { email } = req.body;

  const user = getUser(email) || {
    id: base64url(Buffer.from(email)),
    email,
    devices: [],
  };

  const options = generateRegistrationOptions({
    rpName: "Cyberpunk Terminal",
    rpID: "your-site.netlify.app",
    userID: user.id,
    userName: email,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'discouraged',
      userVerification: 'preferred',
    },
  });

  user.challenge = options.challenge;
  saveUser(email, user);

  res.send(options);
});

router.post('/verify', async (req, res) => {
  const { email, attResp } = req.body;
  const user = getUser(email);

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: attResp,
      expectedChallenge: user.challenge,
      expectedOrigin: 'https://your-site.netlify.app',
      expectedRPID: 'your-site.netlify.app',
    });
  } catch (e) {
    return res.status(400).send({ error: e.message });
  }

  if (!verification.verified) return res.status(400).send({ verified: false });

  user.devices.push(verification.registrationInfo);
  saveUser(email, user);

  res.send({ verified: true });
});

module.exports = router;
