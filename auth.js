const argon2 = require("argon2");

const hashPassword = (req, res, next) => {
  // hash the password using argon2 then call next()
  argon2
    .hash(req.body.password, {
      memoryCost: 15 * 1024,
      timeCost: 2,
      parallelism: 1,
      type: argon2.argon2id,
    })
    .then((hashedPassword) => {
      req.body.hashedPassword = hashedPassword;
      delete req.body.password;
      next();
    })
    .catch((err) => {
      console.error(err);
    });
};

module.exports = {
  hashPassword,
};
