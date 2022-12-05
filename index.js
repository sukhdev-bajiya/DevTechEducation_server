import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

import connection from "./config/index.js";
import AuthRouter from "./middleware/auth.js";
import UserAuthRouter from "./middleware/userauth.js";
import LearnRouter from "./middleware/learn.js";

const app = express();

app.use(cookieParser());
app.use(express.json());
app.use(cors());

app.use("/auth", AuthRouter);
app.use("/user", UserAuthRouter);
app.use("/learn", LearnRouter);

app.get("/", (req, res) => {
  return res.status(200).send("DEV TECH EDUCATION");
});

app.listen(8080, async () => {
  try {
    await connection;
    console.log("Listening on port 8080");
  } catch (error) {
    console.log(error.message);
  }
});
