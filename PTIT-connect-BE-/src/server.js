import express from "express";
import bodyParser from "body-parser";
import viewEngine from "./config/viewEngine";
import initWebRoutes from "./route/web";
import cors from "cors";
require("dotenv").config();

let app = express();

// app.use(bodyParser.json());
// app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "50mb" }));

app.use(
  cors({
    credentials: true,
    origin: true,
  })
);
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "http://localhost:3000");
  // res.header("Access-Control-Allow-Origin", "http://localhost:2003");

  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept"
  );
  next();
});
viewEngine(app);
initWebRoutes(app);

let port = process.env.PORT || 6666;

app.listen(port, () => {
  console.log("BE on port: " + port);
});
