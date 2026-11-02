const express = require("express");
const { exec } = require("child_process");
const mysql = require("mysql");
const app = express();
const db = mysql.createConnection({});
app.get("/u", (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id, (e, r) => res.send(r));
});
app.get("/run", (req, res) => {
  exec("ls " + req.query.dir, (e, out) => res.send(out));
});
app.get("/e", (req, res) => {
  res.send(eval(req.query.code));
});
app.get("/x", (req, res) => {
  document.body.innerHTML = req.query.q;
  res.send("<div>" + req.query.q + "</div>");
});
app.listen(3000);
