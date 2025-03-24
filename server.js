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

app.post("/register", (req, res) => {
  const { name, surname, dni, tlf, email, password } = req.body;

  // Verificar que los campos llegan correctamente
  if (!name || !surname || !dni || !tlf || !email || !password) {
    return res.status(400).json({ error: "Todos los campos son obligatorios" });
  }

  // Registro de usuario
  db.query(
    "INSERT INTO users (name, surname, dni, tlf, email, password, role) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [name, surname, dni, tlf, email, password, "user"],
    (err, result) => {
      if (err) {
        console.error("Error en la base de datos:", err); // 📌 Imprimir error en la terminal

        // Manejar el error 1062 (clave duplicada)
        if (err.errno === 1062) {
          return res.status(400).json({
            error: "Error de duplicación",
            errno: err.errno, // Devolver el código de error
            sqlMessage: err.sqlMessage, // Devolver el mensaje de SQL
          });
        }

        // Otros errores de la base de datos
        return res.status(500).json({
          error: "Error en el servidor",
          details: err.message,
          errno: err.errno, // Devolver el código de error
        });
      }

      // Éxito
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
      const tlf = user.tlf;
      const dni = user.dni;
      const surname = user.surname;
      const id = user.id;
      res.json({
        message: "Login correcto",
        token,
        role,
        name,
        email,
        tlf,
        dni,
        surname,
        id,
      });
    }
  );
});

// 📌 Middleware para validar el token
const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Acceso denegado" });

  jwt.verify(token, "secreto", (err, user) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.user = user;
    next();
  });
};

// 📌 Actualizar perfil
app.put("/update-profile", authenticateToken, async (req, res) => {
  const { name, surname, dni, tlf, email, password } = req.body;
  const userId = req.user.id; // 📌 Sacamos el ID del usuario logueado

  try {
    // 📌 Si el usuario quiere cambiar la contraseña, la encriptamos
    let hashedPassword = null;
    if (password) {
      const salt = await bcrypt.genSalt(10);
      hashedPassword = await bcrypt.hash(password, salt);
    }

    // 📌 Actualizar los datos en la BD
    db.query(
      `UPDATE users SET name = ?, surname = ?, dni = ?, tlf = ?, email = ? 
       ${password ? ", password = ?" : ""} WHERE id = ?`,
      password
        ? [name, surname, dni, tlf, email, hashedPassword, userId]
        : [name, surname, dni, tlf, email, userId],
      (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Perfil actualizado correctamente" });
      }
    );
  } catch (error) {
    res.status(500).json({ error: "Error actualizando el perfil" });
  }
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
