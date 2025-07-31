const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const registerRoutes = require('./routes/register');
const loginRoutes = require('./routes/login');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: 'https://your-site.netlify.app',
  credentials: true
}));
app.use(bodyParser.json());

app.use('/register', registerRoutes);
app.use('/login', loginRoutes);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
