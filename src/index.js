require("dotenv/config");
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { verify } = require("jsonwebtoken");
const { hash, compare } = require("bcrypt");

// Register a user

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

server.listen(process.env.PORT, () =>
  console.log(`Server running at port ${process.env.PORT}`)
);
