require("dotenv/config");
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { verify } = require("jsonwebtoken");
const { hash, compare } = require("bcrypt");
const { database } = require("./data");
const { isAuth } = require("./isAuth");
const {
  createAccessToken,
  createRefreshToken,
  sendAccessToken,
  sendRefreshToken,
} = require("./tokens");

const server = express();

// use express middleware for cookie handling
server.use(cookieParser());

server.use(
  cors({
    // for frontend access
    origin: "http://localhost:3000",
    credentials: true,
  })
);

// for us to be able to ready body data
server.use(express.json());
// support url emcoded bodies
server.use(express.urlencoded({ extended: true }));

// User registration endpoint routes (placed here for now)
server.post("/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    // if user does exist
    const user = database.find((user) => user.email === email);
    if (user) throw new Error("User already exists");

    // if user does not exist, hash the password
    const hashedPassword = await hash(password, 10);
    // insert user in the database
    database.push({
      id: database.length,
      email,
      password: hashedPassword,
    });
    res.send({ message: "User created successfully", data: database });
  } catch (error) {
    res.send({
      error: `${error.message}`,
    });
  }
});

// User Login endpoint
server.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    // Find user in database
    const user = database.find((user) => user.email === email);
    if (!user) throw new Error("User not found");
    // Compare crypted password to see if matches
    const isValid = await compare(password, user.password);
    if (!isValid) throw new Error("Password not correct");
    // Create access and refresh token
    const accessToken = createAccessToken(user.id);
    const refreshToken = createRefreshToken(user.id);
    // Add the refresh token field in the database
    user.refreshToken = refreshToken;
    // send refresh token to the client as a cookie and access token as regular response
    sendRefreshToken(res, refreshToken);
    sendAccessToken(req, res, accessToken);
  } catch (error) {
    res.send({
      error: `${error.message}`,
    });
  }
});

// User logout
server.post("/logout", (_req, res) => {
  res.clearCookie("refreshtoken", { path: "/refresh_token" });
  return res.send({
    message: "Logged out",
  });
});

// Create protected route
server.post("/dashboard", async (req, res) => {
  try {
    const userId = isAuth(req);
    if (userId !== null) {
      res.send({
        data: "This is dashboard data response",
      });
    }
  } catch (error) {
    res.send({
      error: `${error.message}`,
    });
  }
});

// Get new access token by refresh token
server.post("/refresh_token", async (req, res) => {
  // `refreshtoken here is the cookie name
  const token = req.cookies.refreshtoken;
  //if no token
  if (!token) return res.send({ accessToken: "" });
  // if token is there
  let payload = null;

  try {
    payload = verify(token, process.env.REFRESH_TOKEN);
  } catch (error) {
    return res.send({
      accessToken: "",
    });
  }
  // token is valid, then check if user exists as well
  const user = database.find((user) => user.id === payload.userId);
  if (!user) return res.send({ accessToken: "" });
  // user exists, then check if refreshtoken exists on user as well
  if (user.refreshToken !== token) {
    return res.send({ accessToken: "" });
  }

  // token exist, create new refresh, and access token
  const accessToken = createAccessToken(user.id);
  const refreshToken = createRefreshToken(user.id);

  //update refresh token in database
  user.refreshToken = refreshToken;
  sendRefreshToken(res, refreshToken);
  return res.send({ accessToken });
});

// Start server listening on port 5000
server.listen(process.env.PORT, () =>
  console.log(`Server running at port ${process.env.PORT}`)
);
