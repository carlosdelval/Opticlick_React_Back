import express from "express";
import cors from "cors";
import mysql from "mysql2";
import dotenv from "dotenv";

import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Conexión a la base de datos
const db = mysql.createConnection({
  host: "localhost",
  user: "dwes",
  password: "abc123.",
  database: "opticlick_react",
});

db.connect((err) => {
  if (err) {
    console.error("❌ Error al conectar con MySQL:", err);
    return;
  }
  console.log("✅ Conectado a la base de datos MySQL");
});

// Rutas de prueba
app.get("/", (req, res) => {
  res.send("🔥 API funcionando correctamente 🔥");
});

// 📌 Rutas para USUARIOS
app.get("/users", (req, res) => {
  db.query("SELECT * FROM users", (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// Registro de usuario
app.post("/register", (req, res) => {
  const { name, surname, dni, tlf, email, password } = req.body;
  db.query(
    "INSERT INTO users (name, surname, dni, tlf, email, password, role) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [name, surname, dni, tlf, email, password, "user"],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Usuario registrado", id: result.insertId });
    }
  );
});

// 📌 Login de usuario
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) return res.status(500).json({ error: err.message });

      if (results.length === 0)
        return res.status(401).json({ error: "Usuario no encontrado" });

      const user = results[0];
      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch)
        return res.status(401).json({ error: "Contraseña incorrecta" });

      const token = jwt.sign({ id: user.id }, "secreto", { expiresIn: "1h" });
      const role = user.role;
      const name = user.name;
      const email = user.email;
      res.json({ message: "Login correcto", token, role, name, email });
    }
  );
});

// 📌 Rutas para CITAS
app.get("/citas", (req, res) => {
  db.query("SELECT * FROM citas", (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.post("/citas", (req, res) => {
  const { cliente_id, fecha, hora } = req.body;
  db.query(
    "INSERT INTO citas (cliente_id, fecha, hora) VALUES (?, ?, ?)",
    [cliente_id, fecha, hora],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Cita registrada", id: result.insertId });
    }
  );
});

app.delete("/citas/:id", (req, res) => {
  const { id } = req.params;
  db.query("DELETE FROM citas WHERE id = ?", [id], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: "Cita eliminada" });
  });
});

// Escuchar en el puerto
app.listen(port, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${port}`);
});
