const { verify } = require("jsonwebtoken");

const isAuth = (req) => {
  const authorization = req.headers["authorization"];
  if (!authorization) throw new Error("You must login to continue!");
  // get token at index 1 (authorization be like : Bearer 5ghgh6767...)
  const token = authorization.split(" ")[1];
  const { userId } = verify(token, process.env.ACCESS_TOKEN);
  return userId;
};

module.exports = {
  isAuth,
};
