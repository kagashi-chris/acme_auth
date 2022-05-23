const jwt = require("jsonwebtoken");
const Sequelize = require("sequelize");
const bcrypt = require("bcrypt");
const saltRounds = 10;
if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}
const { STRING } = Sequelize;
const config = {
  logging: false,
};

const SECRET_KEY = process.env.JWT;

if (process.env.LOGGING) {
  delete config.logging;
}
// const conn = new Sequelize(
//   process.env.DATABASE_URL || "postgres://localhost/acme_db",
//   config
// );
const conn = new Sequelize(`acme_db`, "postgres", "postgres", {
  host: "localhost",
  dialect: "postgres",
  logging: false,
});

const User = conn.define("user", {
  username: STRING,
  password: STRING,
});

User.beforeCreate(async (user) => {
  const hashPassword = await bcrypt.hash(user.password, saltRounds);
  user.password = hashPassword;
});

User.byToken = async (token) => {
  try {
    const user = jwt.verify(token, SECRET_KEY);
    if (user) {
      return user;
    }
    const error = Error("bad credentials");
    error.status = 401;
    throw error;
  } catch (ex) {
    const error = Error("bad credentials");
    error.status = 401;
    throw error;
  }
};

User.authenticate = async ({ username, password }) => {
  const user = await User.findOne({
    where: {
      username,
    },
  });
  const isUser = await bcrypt.compare(password, user.password);

  if (user && isUser) {
    return jwt.sign({ id: user.id, username: user.username }, SECRET_KEY);
  }

  const error = Error("bad credentials");
  error.status = 401;
  throw error;
};

const syncAndSeed = async () => {
  await conn.sync({ force: true });
  const credentials = [
    { username: "lucy", password: "lucy_pw" },
    { username: "moe", password: "moe_pw" },
    { username: "larry", password: "larry_pw" },
  ];
  const [lucy, moe, larry] = await Promise.all(
    credentials.map((credential) => User.create(credential))
  );
  return {
    users: {
      lucy,
      moe,
      larry,
    },
  };
};

module.exports = {
  syncAndSeed,
  models: {
    User,
  },
};
