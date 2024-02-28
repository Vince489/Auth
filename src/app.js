require("./config/db");
require("dotenv").config();


const express = require("express");
const routes = require("./routes");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const app = express();

const corsOptions = {
  origin: ["http://localhost:3000", "http://localhost:4300", "https://zprompter.com", "https://virtronboxing.club", "https://virtron-beta.netlify.app", "https://virtron-beta.netlify.app/"],
  credentials: true,
};

app.use(express.json());
app.use(cookieParser());
app.use(cors(corsOptions));
app.use("/api/v1", routes);



module.exports = app;
