const users = new Map(); // temporary in-memory storage

module.exports = {
  getUser: (email) => users.get(email),
  saveUser: (email, user) => users.set(email, user),
};
