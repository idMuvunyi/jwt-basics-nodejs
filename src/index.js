require("dotenv/config");
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { verify } = require("jsonwebtoken");
const { hash, compare } = require("bcrypt");
const { database } = require("./data");
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
    console.log(database);
    // send refresh token to the client as a cookie and access token as regular response
    sendRefreshToken(res, refreshToken);
    sendAccessToken(req, res, accessToken);
  } catch (error) {
    res.send({
      error: `${error.message}`,
    });
  }
});

// Start server listening on port 5000
server.listen(process.env.PORT, () =>
  console.log(`Server running at port ${process.env.PORT}`)
);
