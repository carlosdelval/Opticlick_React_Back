import express from "express";
import cors from "cors";
import mysql from "mysql2";
import dotenv from "dotenv";

import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

import { v4 as uuidv4 } from "uuid";
import { sendVerificationEmail } from "./servicios/email.js";

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
  db.query("SELECT * from users WHERE role='user'", (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.get("/admins", (req, res) => {
  db.query(
    "SELECT u.*, uo.optica_id FROM users u JOIN users_opticas uo ON u.id = uo.user_id WHERE u.role='admin'",
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    }
  );
});
// Obtener óptica de un usuario
app.get("/optica-usuario/:id", (req, res) => {
  const { id } = req.params;
  db.query(
    "SELECT optica_id FROM users_opticas WHERE user_id=?",
    [id],
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results[0] || null); // Devuelve el primer resultado o null si no hay registros
    }
  );
});
// Obtener admins de una óptica
app.get("/admins-optica/:id", (req, res) => {
  const { id } = req.params;
  db.query(
    "SELECT * FROM users u JOIN users_opticas ao ON u.id = ao.user_id WHERE u.role='admin' AND ao.optica_id = ?",
    [id],
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    }
  );
});

// Asignar óptica a un usuario
app.put("/asignar-optica", (req, res) => {
  const { user_id, optica_id } = req.body;
  db.query(
    "INSERT INTO users_opticas (user_id, optica_id) VALUES (?, ?)",
    [user_id, optica_id],
    (err) => {
      if (err) {
        console.error("Error en la base de datos:", err);
        return res.status(500).json({
          error: "Error al asignar óptica al usuario",
          details: err.message,
        });
      }
      res.json({ message: "Óptica asignada al usuario" });
    }
  );
});

// Obtener usuario por id
app.get("/users/:id", (req, res) => {
  const { id } = req.params;
  db.query("SELECT * FROM users WHERE id = ?", [id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results[0]);
  });
});

// Obtener usuarios por óptica
app.get("/users-optica/:id", (req, res) => {
  const { id } = req.params;
  db.query(
    "SELECT u.*, uo.optica_id FROM users u JOIN users_opticas uo ON u.id = uo.user_id WHERE u.role='user' AND uo.optica_id = ?",
    [id],
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    }
  );
});

app.put("/users", (req, res) => {
  const { id, name, surname, dni, tlf, email } = req.body;
  // Validación básica
  if (!id || !name || !surname || !dni || !tlf || !email) {
    return res.status(400).json({ error: "Faltan campos requeridos" });
  }
  db.query(
    "UPDATE users SET name = ?, surname = ?, dni = ?, tlf = ?, email = ?, updated_at = NOW() WHERE id = ?",
    [name, surname, dni, tlf, email, id],
    (err, result) => {
      // Check for duplicate email or dni error
      if (err) {
        if (err.errno === 1062) {
          // Duplicate key error
          if (err.message.includes("email")) {
            return res
              .status(400)
              .json({ error: "El email ya está registrado" });
          } else if (err.message.includes("dni")) {
            return res.status(400).json({ error: "El DNI ya está registrado" });
          }
          return res.status(400).json({ error: "Registro duplicado" });
        }
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: "Usuario actualizado" });
    }
  );
});

app.post("/register", (req, res) => {
  const { name, surname, dni, tlf, email, password, role } = req.body;
  const verificationToken = uuidv4();

  // Validación básica
  if (!name || !surname || !dni || !tlf || !email || !password) {
    return res.status(400).json({ error: "Faltan campos requeridos" });
  }

  // Encriptar la contraseña
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);

  db.query(
    "INSERT INTO users (name, surname, dni, tlf, email, password, role, created_at, updated_at, remember_token) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), ?)",
    [name, surname, dni, tlf, email, hashedPassword, role, verificationToken],
    async (err, result) => {
      if (err) {
        console.error("Error en la base de datos:", err);
        if (err.errno === 1062) {
          if (err.message.includes("email")) {
            return res
              .status(400)
              .json({ error: "El email ya está registrado" });
          } else if (err.message.includes("dni")) {
            return res.status(400).json({ error: "El DNI ya está registrado" });
          }
          return res.status(400).json({ error: "Registro duplicado" });
        }

        return res.status(500).json({
          error: "Error en el servidor",
          details: err.message,
          errno: err.errno,
        });
      }
      const userId = result.insertId;
      try {
        await sendVerificationEmail(email, verificationToken);
        res.json({
          id: userId,
          message:
            "Usuario registrado. Verifica tu email para activar la cuenta.",
        });
      } catch (emailErr) {
        console.error("Error enviando email:", emailErr.message);
        res
          .status(500)
          .json({ error: "Error enviando el email de verificación" });
      }
    }
  );
});

// Ruta para verificar el email
app.get("/verify-email/:token", (req, res) => {
  const { token } = req.params;

  db.query(
    "SELECT * FROM users WHERE remember_token = ?",
    [token],
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });

      if (results.length === 0) {
        return res.status(400).json({ error: "Token inválido o expirado" });
      }

      db.query(
        "UPDATE users SET email_verified_at = ?, remember_token = NULL WHERE remember_token = ?",
        [new Date(), token],
        (err2) => {
          if (err2) return res.status(500).json({ error: err2.message });
          res.json({
            message:
              "Email verificado correctamente. Ahora puedes iniciar sesión.",
            email: results[0].email,
            role: results[0].role,
            name: results[0].name,
            tlf: results[0].tlf,
            dni: results[0].dni,
            surname: results[0].surname,
            id: results[0].id,
            email_verified: results[0].email_verified_at,
            token: jwt.sign({ id: results[0].id }, "secreto", {
              expiresIn: "24h",
            }),
          });
        }
      );
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
      const email_verified = user.email_verified_at;
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
        email_verified,
      });
    }
  );
});

// Login con Google
app.post("/login-google", async (req, res) => {
  const { email, name } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email es requerido" });
  }

  try {
    db.query(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (err, results) => {
        if (err) {
          console.error("Database error:", err);
          return res
            .status(500)
            .json({ error: "Database error", details: err.message });
        }

        let user;

        if (results.length === 0) {
          // Crear nuevo usuario
          const newUser = {
            email,
            name: name || email.split("@")[0], // Usa el nombre o parte del email
            role: "user",
            password: bcrypt.hashSync(email, 10), // Contraseña por defecto para Google
            created_at: new Date(),
            updated_at: new Date(),
            email_verified_at: new Date(), // Google ya verificó el email
          };

          db.query("INSERT INTO users SET ?", newUser, (err, result) => {
            if (err) {
              console.error("Error creating user:", err);
              return res
                .status(500)
                .json({ error: "Error creating user", details: err.message });
            }

            user = {
              id: result.insertId,
              ...newUser,
            };

            const token = jwt.sign(
              { id: user.id },
              process.env.JWT_SECRET || "secreto",
              { expiresIn: "24h" }
            );

            return res.json({
              token,
              role: user.role,
              email: user.email,
              name: user.name,
              id: user.id,
              email_verified: user.email_verified_at,
            });
          });
        } else {
          // Usuario existente
          user = results[0];
          const token = jwt.sign(
            { id: user.id },
            process.env.JWT_SECRET || "secreto",
            { expiresIn: "24h" }
          );

          // En tu endpoint /login-google
          return res.json({
            token,
            role: user.role,
            email: user.email,
            name: user.name || name,
            tlf: user.tlf || null, // Asegúrate de incluir todos los campos
            dni: user.dni || null,
            surname: user.surname || null,
            id: user.id,
            email_verified: user.email_verified_at,
          });
        }
      }
    );
  } catch (error) {
    console.error("Server error:", error);
    res
      .status(500)
      .json({ error: "Internal server error", details: error.message });
  }
});

// Reenviar email de verificación
app.post("/resend-email", (req, res) => {
  const { email } = req.body;
  const verificationToken = uuidv4();
  db.query(
    "UPDATE users SET remember_token = ? WHERE email = ?",
    [verificationToken, email],
    async (err, result) => {
      if (err) {
        console.error("Error en la base de datos:", err);
        return res.status(500).json({
          error: "Error en el servidor",
          details: err.message,
          errno: err.errno,
        });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "Usuario no encontrado" });
      }
      // Enviar email de verificación
      try {
        await sendVerificationEmail(email, verificationToken);
        res.json({
          message:
            "Email de verificación reenviado. Revisa tu bandeja de entrada.",
        });
      } catch (emailErr) {
        console.error("Error enviando email:", emailErr.message);
        res.status(500).json({
          error: "Error enviando el email de verificación",
        });
      }
    }
  );
});

// 📌 Middleware para validar el token
const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Acceso denegado" });

  jwt.verify(token, "secreto", (err, user) => {
    if (err)
      return res.status(403).json({
        error: "Su inicio de sesión ha caducado, debe logear de nuevo.",
      });
    req.user = user;
    next();
  });
};

// 📌 Actualizar perfil
app.put("/update-profile", authenticateToken, async (req, res) => {
  const { name, surname, dni, tlf, email, password, optica } = req.body;
  const userId = req.user.id; // 📌 Sacamos el ID del usuario logueado

  try {
    // 📌 Si el usuario quiere cambiar la contraseña, la encriptamos
    let hashedPassword = null;
    if (password) {
      const salt = await bcrypt.genSalt(10);
      hashedPassword = await bcrypt.hash(password, salt);
    }

    if (email) {
      // 📌 Comprobar si el email ya está registrado
      db.query(
        "SELECT * FROM users WHERE email = ? AND id != ?",
        [email, userId],
        (err, results) => {
          if (err) return res.status(500).json({ error: err.message });
          if (results.length > 0)
            return res.status(400).json({ error: "Email ya registrado" });
        }
      );
    }

    // 📌 Comprobar si el DNI ya está registrado
    if (dni) {
      db.query(
        "SELECT * FROM users WHERE dni = ? AND id != ?",
        [dni, userId],
        (err, results) => {
          if (err) return res.status(500).json({ error: err.message });
          if (results.length > 0)
            return res.status(400).json({ error: "DNI ya registrado" });
        }
      );
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

// 📌 Eliminar usuario de una óptica

app.delete("/users-optica/:id/:optica_id", (req, res) => {
  const { id, optica_id } = req.params;
  db.query(
    "DELETE FROM users_opticas WHERE user_id = ? AND optica_id = ?",
    [id, optica_id],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Usuario eliminado" });
    }
  );
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
    "SELECT c.*, u.name as user_name, u.surname as user_surname, u.tlf as telefono, o.nombre as optica_nombre FROM citas c JOIN users u ON c.user_id = u.id JOIN opticas o ON c.optica_id = o.id WHERE c.graduada = 0 ORDER BY c.fecha, c.hora",
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    }
  );
});

//Obtener todas las citas de un usuario
app.get("/citas-user/:id", (req, res) => {
  const { id } = req.params;
  db.query(
    "SELECT c.*, o.nombre as optica_nombre FROM citas c JOIN opticas o ON c.optica_id = o.id WHERE c.user_id = ? AND c.graduada = 0 ORDER BY c.fecha, c.hora",
    [id],
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    }
  );
});

//Obtener todas las citas graduadas de un usuario
app.get("/citas-graduadas/:id", (req, res) => {
  const { id } = req.params;
  db.query(
    "SELECT c.*, o.nombre as optica_nombre FROM citas c JOIN opticas o ON c.optica_id = o.id WHERE c.user_id = ? AND c.graduada = 1 ORDER BY c.fecha, c.hora",
    [id],
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    }
  );
});

app.get("/user-citas/:id", (req, res) => {
  const { id } = req.params;
  db.query("SELECT * FROM users WHERE id = ?", [id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// Obtener citas sin graduar por óptica
app.get("/citas-optica/:id", (req, res) => {
  const { id } = req.params;
  db.query(
    "SELECT c.*, u.name as user_name, u.surname as user_surname, u.tlf as telefono FROM citas c JOIN users u ON c.user_id = u.id WHERE c.optica_id = ? AND c.graduada = 0 ORDER BY c.fecha, c.hora",
    [id],
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    }
  );
});

// Obtener las horas de las citas reservadas en una fecha de una optica
app.get("/citas-reservadas/:id/:fecha", (req, res) => {
  const { id, fecha } = req.params;
  db.query(
    "SELECT * FROM citas WHERE optica_id = ? AND fecha = ?",
    [id, fecha],
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    }
  );
});

//obtener cita por fecha, hora y optica_id
app.get("/citas/:fecha/:hora/:optica_id", (req, res) => {
  const { fecha, hora, optica_id } = req.params;
  db.query(
    "SELECT * FROM citas WHERE fecha = ? AND hora = ? AND optica_id = ?",
    [fecha, hora, optica_id],
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results[0] || null); // Devuelve el primer resultado o null si no hay registros
    }
  );
});

app.post("/citas", (req, res) => {
  const { user_id, optica_id, fecha, hora } = req.body;
  db.query(
    "INSERT INTO citas (user_id, optica_id, fecha, hora, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(), NOW())",
    [user_id, optica_id, fecha, hora],
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
    "SELECT eje,cilindro,esfera FROM graduaciones WHERE cita_id = ?",
    [id],
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });

      // Devuelve el primer resultado o null si no hay registros
      res.json(results[0] || null);
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

app.put("/graduaciones/:id", (req, res) => {
  const { id } = req.params;
  db.query(
    "UPDATE graduaciones SET eje = ?, cilindro = ?, esfera = ? WHERE cita_id = ?",
    [req.body.eje, req.body.cilindro, req.body.esfera, id],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Graduación actualizada" });
    }
  );
});

app.delete("/graduaciones/:id", (req, res) => {
  const { id } = req.params;
  db.query(
    "DELETE FROM graduaciones WHERE cita_id = ?",
    [id],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Graduación eliminada" });
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

// 📌 Rutas para ÓPTICAS
app.get("/opticas", (req, res) => {
  db.query("SELECT * FROM opticas", (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.get("/opticas/:id", (req, res) => {
  const { id } = req.params;
  db.query("SELECT * FROM opticas WHERE id = ?", [id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});
app.post("/opticas", (req, res) => {
  const { nombre, direccion, telefono } = req.body;
  // Validación básica
  if (!nombre || !direccion || !telefono) {
    return res.status(400).json({ error: "Faltan campos requeridos" });
  }
  db.query(
    "INSERT INTO opticas (nombre, direccion, telefono, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())",
    [nombre, direccion, telefono],
    (err, result) => {
      if (err) {
        console.error("Error en la base de datos:", err);
        return res.status(500).json({
          error: "Error al crear la óptica",
          details: err.message,
          errno: err.errno,
        });
      }
      res.json({
        message: "Óptica registrada",
        id: result.insertId,
      });
    }
  );
});

app.put("/opticas/:id", (req, res) => {
  const { id } = req.params;
  const { nombre, direccion, telefono } = req.body;
  // Validación básica
  if (!nombre || !direccion || !telefono) {
    return res.status(400).json({ error: "Faltan campos requeridos" });
  }
  db.query(
    "UPDATE opticas SET nombre = ?, direccion = ?, telefono = ?, updated_at = NOW() WHERE id = ?",
    [nombre, direccion, telefono, id],
    (err, result) => {
      if (err) {
        console.error("Error en la base de datos:", err);

        return res.status(500).json({
          error: "Error al actualizar la óptica",
          details: err.message,
          errno: err.errno,
        });
      }
      res.json({ message: "Óptica actualizada" });
    }
  );
});
app.delete("/opticas/:id", (req, res) => {
  const { id } = req.params;
  db.query("DELETE FROM opticas WHERE id = ?", [id], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: "Óptica eliminada" });
  });
});

//📌 Rutas para NOTIFICACIONES
// Obtener todas las notificaciones sin leer (para usuario o admin)
app.get("/notificaciones/:destinatario/:id/:tipo", (req, res) => {
  const { destinatario, id, tipo } = req.params;

  // Determinar qué campo usar en la consulta según el destinatario
  const campoId = destinatario === "1" ? "user_id" : "optica_id";

  db.query(
    `SELECT * FROM notificaciones WHERE ${campoId} = ? AND tipo = ? AND destinatario = ? AND leida = 0 ORDER BY created_at DESC`,
    [id, tipo, destinatario],
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    }
  );
});

app.post("/notificaciones", (req, res) => {
  const { user_id, optica_id, titulo, descripcion, tipo, destinatario } =
    req.body;

  // Validación básica
  if (!user_id || !optica_id || !titulo) {
    return res.status(400).json({ error: "Faltan campos requeridos" });
  }

  db.query(
    "INSERT INTO notificaciones (optica_id, user_id, titulo, descripcion, tipo, destinatario, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())",
    [optica_id, user_id, titulo, descripcion, tipo, destinatario],
    (err, result) => {
      if (err) {
        console.error("Error en la base de datos:", err);
        return res.status(500).json({
          error: "Error al crear la notificación",
          details: err.message,
        });
      }
      res.json({
        message: "Notificación registrada",
        id: result.insertId,
      });
    }
  );
});

//Marcar notificación como leída
app.put("/notificaciones/:id", (req, res) => {
  const { id } = req.params;
  db.query(
    "UPDATE notificaciones SET leida = 1 WHERE id = ?",
    [id],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Notificación marcada como leída" });
    }
  );
});

// Escuchar en el puerto
app.listen(port, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${port}`);
});
