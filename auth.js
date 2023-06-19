const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

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
      req.body.password = hashedPassword;
      next();
    })
    .catch((err) => {
      console.error(err);
    });
};

const verifyPassword = (req, res) => {
  console.log(req.user.password, req.body.password);
  argon2
    .verify(req.user.password, req.body.password)
    .then((isVerified) => {
      if (isVerified) {
        const token = jwt.sign(
          {
            sub: req.user.id,
          },
          process.env.JWT_SECRET,
          {
            expiresIn: "1h",
          }
        );
        delete req.user.password;
        res.send({ token, user: req.user });
      } else {
        res.sendStatus(401);
      }
    })
    .catch((err) => {
      console.error(err);
      res.sendStatus(500);
    });
};

const verifyToken = (req, res, next) => {
  try {
    if (
      !req.headers.authorization ||
      req.headers.authorization.split(" ")[0] !== "Bearer"
    ) {
      return res.sendStatus(401);
    }
    console.log(req.headers.authorization);
    const token = req.headers.authorization.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.payload = decoded;

    next();
  } catch (err) {
    console.error(err);
    res.sendStatus(401);
  }
};

module.exports = {
  hashPassword,
  verifyPassword,
  verifyToken,
};
