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
  db.query("SELECT * FROM users WHERE role='user'", (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.put("/users", (req, res) => {
  const { id, name, surname, dni, tlf, email } = req.body;
  db.query(
    "UPDATE users SET name = ?, surname = ?, dni = ?, tlf = ?, email = ?, updated_at = NOW() WHERE id = ?",
    [name, surname, dni, tlf, email, id],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Usuario actualizado" });
    }
  );
});

app.post("/register", (req, res) => {
  const { name, surname, dni, tlf, email, password } = req.body;

  // Verificar que los campos llegan correctamente
  if (!name || !surname || !dni || !tlf || !email || !password) {
    return res.status(400).json({ error: "Todos los campos son obligatorios" });
  }

  // Registro de usuario
  db.query(
    "INSERT INTO users (name, surname, dni, tlf, email, password, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())",
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

      const token = jwt.sign({ id: user.id }, "secreto", { expiresIn: "24h" });
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
    if (err) return res.status(403).json({ error: "Su inicio de sesión ha caducado, debe logear de nuevo." });
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
       ${password ? ", password = ?" : ", updated_at = NOW()"} WHERE id = ?`,
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

// 📌 Eliminar usuario

app.delete("/users/:id", (req, res) => {
  const { id } = req.params;
  db.query("DELETE FROM users WHERE id = ?", [id], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: "Usuario eliminado" });
  });
});

// 📌 Update SOLO contraseña

app.put("/update-password", authenticateToken, async (req, res) => {
  const { password, new_password } = req.body;
  const userId = req.user.id; // 📌 Sacamos el ID del usuario logueado

  try {
    // 📌 Buscar el usuario en la BD
    db.query(
      "SELECT * FROM users WHERE id = ?",
      [userId],
      async (err, results) => {
        if (err) return res.status(500).json({ error: err.message });

        if (results.length === 0)
          return res.status(404).json({ error: "Usuario no encontrado" });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch)
          return res.status(401).json({ error: "Contraseña incorrecta" });

        // 📌 Encriptar la nueva contraseña
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(new_password, salt);

        // 📌 Actualizar la contraseña en la BD
        db.query(
          "UPDATE users SET password = ? WHERE id = ?",
          [hashedPassword, userId],
          (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: "Contraseña actualizada correctamente" });
          }
        );
      }
    );
  } catch (error) {
    res.status(500).json({ error: "Error actualizando la contraseña" });
  }
});

// 📌 Rutas para CITAS
app.get("/citas", (req, res) => {
  db.query(
    "SELECT * FROM citas WHERE graduada = 0 ORDER BY fecha,hora",
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    }
  );
});

//Obtener todas las citas de un usuario
app.get("/citas-user/:id", (req, res) => {
  const { id } = req.params;
  db.query("SELECT * FROM citas WHERE user_id = ? ORDER BY fecha,hora", [id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.get("/user-citas/:id", (req, res) => {
  const { id } = req.params;
  db.query("SELECT * FROM users WHERE id = ?", [id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.post("/citas", (req, res) => {
  const { cliente_id, fecha, hora } = req.body;
  db.query(
    "INSERT INTO citas (cliente_id, fecha, hora, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())",
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

// 📌 Rutas para GRADUACIONES

app.get("/graduaciones/:id", (req, res) => {
  const { id } = req.params;
  db.query(
    "SELECT * FROM graduaciones WHERE cita_id = ?",
    [id],
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    }
  );
});

app.post("/graduaciones", (req, res) => {
  db.query(
    "INSERT INTO graduaciones (cita_id, eje, cilindro, esfera, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(), NOW())",
    [req.body.cita_id, req.body.eje, req.body.cilindro, req.body.esfera],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Graduación registrada", id: result.insertId });
    }
  );
});

// 📌 Marcar cita como graduada
app.put("/citas/:id", (req, res) => {
  const { id } = req.params;
  db.query(
    "UPDATE citas SET graduada = 1 WHERE id = ?",
    [id],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Cita graduada" });
    }
  );
});

// Escuchar en el puerto
app.listen(port, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${port}`);
});
