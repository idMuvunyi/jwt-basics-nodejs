require("dotenv/config");
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { verify } = require("jsonwebtoken");
const { hash, compare } = require("bcrypt");
const { database } = require("./data");
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

// endpoint routes (placed here for now)
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
