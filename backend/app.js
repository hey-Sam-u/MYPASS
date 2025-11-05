// ✅ Load environment variables
const dotenv = require("dotenv");
dotenv.config();

const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const router = express.Router();

const app = express();
app.use(cors());
app.use(express.json());

// ✅ MySQL connection setup
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error("❌ Database connection failed:", err.message);
  } else {
    console.log("✅ Connected to MySQL Database.");
  }
});

// ✅ Register endpoint
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;

  // Basic validation
  if (!name || !email || !password)
    return res.status(400).json({ msg: "All fields are required" });

  // Email format check
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email))
    return res.status(400).json({ msg: "Invalid email format" });

  // Password rules
  if (password.length < 10)
    return res
      .status(400)
      .json({ msg: "Password must be at least 10 characters long" });

  // Prevent using part of email in password
  const localPart = email.split("@")[0].toLowerCase();
  if (password.toLowerCase().includes(localPart))
    return res
      .status(400)
      .json({ msg: "Password should not contain part of your email" });

  // Check existing user
  db.query(
    "SELECT id FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) return res.status(500).json({ msg: "Database error" });
      if (results.length > 0)
        return res.status(409).json({ msg: "Email already registered" });

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 12);

      // Insert user
      db.query(
        "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
        [name, email, hashedPassword],
        (err2) => {
          if (err2)
            return res.status(500).json({ msg: "Database insert failed" });
          res.status(201).json({ msg: "Account created successfully" });
        }
      );
    }
  );
});

const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;

// ✅ LOGIN (debug version)
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log("📩 Login request received:", email);

    if (!email || !password)
      return res.status(400).json({ msg: "All fields are required" });

    db.query(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (err, result) => {
        if (err) {
          console.error("❌ DB error:", err);
          return res.status(500).json({ msg: "Database error" });
        }

        if (result.length === 0) {
          console.log("⚠️ No user found for:", email);
          return res.status(401).json({ msg: "Invalid credentials" });
        }

        const user = result[0];
        console.log("✅ User found:", user.email);

        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) {
          console.log("❌ Wrong password for:", email);
          return res.status(401).json({ msg: "Invalid credentials" });
        }

        console.log("🔑 Password verified, generating token...");
        const token = jwt.sign(
          { id: user.id, email: user.email, name: user.name },
          process.env.JWT_SECRET,
          { expiresIn: "2h" }
        );

        console.log("✅ Token created successfully!");
        res.json({
          msg: "Login successful",
          token,
          user: { id: user.id, name: user.name, email: user.email },
        });
      }
    );
  } catch (err) {
    console.error("🔥 Unexpected Error:", err);
    res.status(500).json({ msg: "Internal Server Error" });
  }
});

function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  console.log("🔍 Auth Header:", authHeader); // debug

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(403).json({ message: "No token provided." });
  }

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.log("❌ Invalid token:", err.message);
      return res.status(401).json({ message: "Invalid or expired token." });
    }
    req.user = decoded;
    next();
  });
}

// ✅ Example protected route
app.get("/api/dashboard", verifyToken, (req, res) => {
  res.json({
    message: `Welcome ${req.user.name}!`,
    email: req.user.email,
  });
});

// storage engine: put files under backend/uploads/<userId>/
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // req.user should exist because verifyToken runs before this route
    const userId = req.user && req.user.id ? String(req.user.id) : "anonymous";
    const uploadDir = path.join(__dirname, "..", "uploads", userId);
    fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    // create a unique stored filename
    const ts = Date.now();
    const safe = file.originalname.replace(/\s+/g, "_");
    const stored = `${ts}_${Math.round(Math.random() * 1e6)}_${safe}`;
    cb(null, stored);
  },
});

// limit (adjust maxSize as needed)
const upload = multer({
  storage,
  limits: { fileSize: 200 * 1024 * 1024 }, // 200 MB max (change if needed)
});

// helper to map mime to our file_type enum
function guessFileType(mime) {
  if (!mime) return "other";
  if (mime.startsWith("image/")) return "image";
  if (mime === "application/pdf") return "pdf";
  if (mime.startsWith("text/")) return "text";
  return "other";
}

// POST /api/upload
// expects multipart/form-data with:
// - file (the encrypted blob)
// - filename_original, mime_type, size_bytes, salt, iv
app.post("/api/upload", verifyToken, upload.single("file"), (req, res) => {
  try {
    // req.user comes from verifyToken
    const ownerId = req.user && req.user.id ? req.user.id : null;
    if (!ownerId) return res.status(401).json({ msg: "Unauthorized" });

    if (!req.file) {
      return res.status(400).json({ msg: "No file uploaded" });
    }

    // read metadata fields
    const { filename_original, mime_type, size_bytes, salt, iv } = req.body;
    const filenameStored = req.file.filename;
    const storedPath = req.file.path; // full path on server
    const fileSize = req.file.size || (size_bytes ? Number(size_bytes) : 0);

    const fileType = guessFileType(mime_type);

    // insert into DB
    const sql = `INSERT INTO files
      (owner_id, filename_original, filename_stored, mime_type, file_type, size_bytes, salt, iv)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;

    db.query(
      sql,
      [
        ownerId,
        filename_original || req.file.originalname,
        filenameStored,
        mime_type || req.file.mimetype,
        fileType,
        fileSize,
        salt || null,
        iv || null,
      ],
      (err, result) => {
        if (err) {
          console.error("Upload DB insert error:", err);
          // cleanup file on disk if DB failed
          try {
            fs.unlinkSync(storedPath);
          } catch (e) {}
          return res.status(500).json({ msg: "Database error" });
        }

        const insertedId = result.insertId;
        return res.json({
          msg: "Upload successful",
          fileId: insertedId,
          storedName: filenameStored,
        });
      }
    );
  } catch (err) {
    console.error("Upload route error:", err);
    return res.status(500).json({ msg: "Upload failed" });
  }
});

// === List all files for logged-in user ===
app.get("/api/files", verifyToken, (req, res) => {
  const userId = req.user.id;
  const sql = `
    SELECT id, filename_original, file_type, size_bytes, uploaded_at
    FROM files
    WHERE owner_id = ?
    ORDER BY uploaded_at DESC
  `;
  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error("File list DB error:", err);
      return res.status(500).json({ msg: "Database error" });
    }
    res.json({ files: results });
  });
});

// 🧹 Delete a file by ID
app.delete("/api/files/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    // Check if file belongs to user
    const checkSql = "SELECT * FROM files WHERE id = ? AND owner_id = ?";
    db.query(checkSql, [id, userId], (err, results) => {
      if (err) {
        console.error("DB check error:", err);
        return res.status(500).json({ msg: "Database error" });
      }
      if (results.length === 0) {
        return res.status(404).json({ msg: "File not found or unauthorized" });
      }

      // Delete file from DB
      const deleteSql = "DELETE FROM files WHERE id = ?";
      db.query(deleteSql, [id], (err2) => {
        if (err2) {
          console.error("DB delete error:", err2);
          return res.status(500).json({ msg: "Database delete error" });
        }

        // Delete physical file from disk
        const filePath = path.join(
          __dirname,
          "..",
          "uploads",
          String(userId),
          results[0].filename_stored
        );
        try {
          fs.unlinkSync(filePath);
        } catch (e) {
          console.warn("File missing on disk:", e.message);
        }

        res.json({ msg: "File deleted successfully ✅" });
      });
    });
  } catch (err) {
    console.error("Delete error:", err);
    res.status(500).json({ msg: "Server error while deleting file" });
  }
});

// === View/Download a file by ID ===
app.get("/api/files/:id", verifyToken, (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  const sql = "SELECT * FROM files WHERE id = ? AND owner_id = ?";
  db.query(sql, [id, userId], (err, results) => {
    if (err) {
      console.error("DB fetch error:", err);
      return res.status(500).json({ msg: "Database error" });
    }
    if (results.length === 0) {
      return res.status(404).json({ msg: "File not found or unauthorized" });
    }

    const file = results[0];
    const filePath = path.join(
      __dirname,
      "..",
      "uploads",
      String(userId),
      file.filename_stored
    );

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ msg: "File missing on server" });
    }

    // send as file stream
    res.setHeader("Content-Type", file.mime_type || "application/octet-stream");
    res.setHeader(
      "Content-Disposition",
      `inline; filename="${file.filename_original}"`
    );

    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);
  });
});

// === File metadata (salt, iv, mime, original name) - used for client-side decryption ===
app.get("/api/files/:id/meta", verifyToken, (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  const sql =
    "SELECT id, filename_original, filename_stored, mime_type, salt, iv, size_bytes FROM files WHERE id = ? AND owner_id = ?";
  db.query(sql, [id, userId], (err, results) => {
    if (err) {
      console.error("Meta DB error:", err);
      return res.status(500).json({ msg: "Database error" });
    }
    if (results.length === 0) {
      return res.status(404).json({ msg: "File not found or unauthorized" });
    }

    const file = results[0];
    // salt & iv stored as base64 in DB (we stored them that way earlier). Send them as-is.
    res.json({
      id: file.id,
      filename_original: file.filename_original,
      mime_type: file.mime_type,
      size_bytes: file.size_bytes,
      salt: file.salt,
      iv: file.iv,
    });
  });
});
//user owen password vault root
// Create password entry (store encrypted blob + salt+iv + title, login, notes)
app.post("/api/passwords", verifyToken, (req, res) => {
  const { title, login, notes, encrypted_blob, salt, iv } = req.body;
  const ownerId = req.user.id;
  if (!title || !encrypted_blob || !salt || !iv) {
    return res.status(400).json({ msg: "Missing required fields" });
  }

  const sql = `INSERT INTO passwords (owner_id, title, login, notes, encrypted_blob, salt, iv)
               VALUES (?, ?, ?, ?, ?, ?, ?)`;
  db.query(
    sql,
    [ownerId, title, login || null, notes || null, encrypted_blob, salt, iv],
    (err, result) => {
      if (err) {
        console.error("Passwords insert error:", err);
        return res.status(500).json({ msg: "Database error" });
      }
      res.json({ msg: "Saved", id: result.insertId });
    }
  );
});

// List entries for user (no encrypted blob here — only metadata)
app.get("/api/passwords", verifyToken, (req, res) => {
  const ownerId = req.user.id;
  const sql = `SELECT id, title, login, notes, created_at, updated_at FROM passwords
               WHERE owner_id = ? ORDER BY updated_at DESC`;
  db.query(sql, [ownerId], (err, results) => {
    if (err) return res.status(500).json({ msg: "DB error" });
    res.json({ items: results });
  });
});

// Meta: salt/iv/filename — needed before decrypting
app.get("/api/passwords/:id/meta", verifyToken, (req, res) => {
  const ownerId = req.user.id;
  const id = req.params.id;
  const sql = `SELECT id, title, login, notes, salt, iv FROM passwords WHERE id = ? AND owner_id = ?`;
  db.query(sql, [id, ownerId], (err, results) => {
    if (err) return res.status(500).json({ msg: "DB error" });
    if (results.length === 0) return res.status(404).json({ msg: "Not found" });
    res.json(results[0]);
  });
});

// Get encrypted blob (for decrypting client-side)
app.get("/api/passwords/:id", verifyToken, (req, res) => {
  const ownerId = req.user.id;
  const id = req.params.id;
  const sql = `SELECT encrypted_blob, mime_type FROM passwords WHERE id = ? AND owner_id = ?`;
  db.query(sql, [id, ownerId], (err, results) => {
    if (err) return res.status(500).json({ msg: "DB error" });
    if (results.length === 0) return res.status(404).json({ msg: "Not found" });
    // send raw data; if stored base64 text, send as json {blob: ...} instead
    const blob = results[0].encrypted_blob;
    res.setHeader(
      "Content-Type",
      results[0].mime_type || "application/octet-stream"
    );
    // If encrypted_blob is base64 text in DB:
    // const buff = Buffer.from(blob, 'base64'); res.send(buff);
    res.send(blob); // adjust if you store text
  });
});

// Update (rename or re-encrypt)
app.put("/api/passwords/:id", verifyToken, (req, res) => {
  const ownerId = req.user.id;
  const id = req.params.id;
  const { title, login, notes, encrypted_blob, salt, iv } = req.body;
  // You can support partial updates (only title change) or full re-encrypt
  const sql = `UPDATE passwords SET title = ?, login = ?, notes = ?, encrypted_blob = COALESCE(?, encrypted_blob),
               salt = COALESCE(?, salt), iv = COALESCE(?, iv) WHERE id = ? AND owner_id = ?`;
  db.query(
    sql,
    [
      title,
      login,
      notes,
      encrypted_blob || null,
      salt || null,
      iv || null,
      id,
      ownerId,
    ],
    (err) => {
      if (err) return res.status(500).json({ msg: "DB error" });
      res.json({ msg: "Updated" });
    }
  );
});

// Delete
app.delete("/api/passwords/:id", verifyToken, (req, res) => {
  const ownerId = req.user.id;
  const id = req.params.id;
  const sql = `DELETE FROM passwords WHERE id = ? AND owner_id = ?`;
  db.query(sql, [id, ownerId], (err, result) => {
    if (err) return res.status(500).json({ msg: "DB error" });
    if (result.affectedRows === 0)
      return res.status(404).json({ msg: "Not found" });
    res.json({ msg: "Deleted" });
  });
});

//change id password
// ✅ CHANGE PASSWORD ROUTE (secured)
app.post("/api/change-password", verifyToken, async (req, res) => {
  try {
    const { current, newPass } = req.body;
    const userId = req.user.id; // token se user id milega

    if (!current || !newPass) {
      return res.status(400).json({ msg: "Both fields are required" });
    }

    // Fetch user from DB
    db.query(
      "SELECT password_hash FROM users WHERE id = ?",
      [userId],
      async (err, results) => {
        if (err) {
          console.error("DB error:", err);
          return res.status(500).json({ msg: "Database error" });
        }
        if (results.length === 0) {
          return res.status(404).json({ msg: "User not found" });
        }

        const isMatch = await bcrypt.compare(current, results[0].password_hash);
        if (!isMatch) {
          return res.status(400).json({ msg: "Incorrect current password" });
        }

        // Hash new password
        const hashed = await bcrypt.hash(newPass, 12);

        db.query(
          "UPDATE users SET password_hash = ? WHERE id = ?",
          [hashed, userId],
          (err2) => {
            if (err2) {
              console.error("Update error:", err2);
              return res.status(500).json({ msg: "Password update failed" });
            }

            res.json({ msg: "Password updated successfully ✅" });
          }
        );
      }
    );
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ msg: "Internal server error" });
  }
});
// === Change Email ===
app.post("/api/change-email", verifyToken, (req, res) => {
  try {
    const userId = req.user && req.user.id;
    const { current, newEmail } = req.body;

    if (!current || !newEmail) {
      return res.status(400).json({ msg: "Both fields required" });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(newEmail)) {
      return res.status(400).json({ msg: "Invalid email format" });
    }

    // 1) fetch user
    db.query(
      "SELECT id, email, password_hash FROM users WHERE id = ?",
      [userId],
      async (err, results) => {
        if (err) {
          console.error("DB error:", err);
          return res.status(500).json({ msg: "Database error" });
        }
        if (!results || results.length === 0) {
          return res.status(404).json({ msg: "User not found" });
        }

        const user = results[0];

        // 2) verify current password
        const ok = await bcrypt.compare(current, user.password_hash);
        if (!ok)
          return res.status(401).json({ msg: "Incorrect current password" });

        // 3) check newEmail not used by someone else
        db.query(
          "SELECT id FROM users WHERE email = ? AND id != ?",
          [newEmail, userId],
          (err2, rows) => {
            if (err2) {
              console.error("DB error:", err2);
              return res.status(500).json({ msg: "Database error" });
            }
            if (rows && rows.length > 0) {
              return res.status(409).json({ msg: "Email already in use" });
            }

            // 4) update
            db.query(
              "UPDATE users SET email = ? WHERE id = ?",
              [newEmail, userId],
              (err3) => {
                if (err3) {
                  console.error("DB update error:", err3);
                  return res
                    .status(500)
                    .json({ msg: "Failed to update email" });
                }

                // optional: you might want to re-issue token with new email on client side
                return res.json({ msg: "Email updated successfully" });
              }
            );
          }
        );
      }
    );
  } catch (err) {
    console.error("change-email error:", err);
    res.status(500).json({ msg: "Server error" });
  }
});
// ✅ CHANGE NAME ROUTE
app.post("/api/user/change-name", verifyToken, (req, res) => {
  const { newName } = req.body;
  const userId = req.user.id;

  if (!newName || newName.trim().length < 3) {
    return res
      .status(400)
      .json({ msg: "Name must be at least 3 characters long" });
  }

  const sql = "UPDATE users SET name = ? WHERE id = ?";
  db.query(sql, [newName.trim(), userId], (err, result) => {
    if (err) {
      console.error("DB update error:", err);
      return res.status(500).json({ msg: "Database error" });
    }

    res.json({ msg: "Name updated successfully ✅", newName });
  });
});

// === Delete account (protected)
app.post("/api/delete-account", verifyToken, (req, res) => {
  try {
    const ownerId = req.user && req.user.id;
    const { email, password, reason } = req.body;

    if (!ownerId) return res.status(401).json({ msg: "Unauthorized" });
    if (!email || !password)
      return res.status(400).json({ msg: "Email and password required" });

    // 1) fetch user to verify password and email match
    db.query(
      "SELECT id, email, password_hash FROM users WHERE id = ?",
      [ownerId],
      async (err, results) => {
        if (err) {
          console.error("DB error fetching user for delete:", err);
          return res.status(500).json({ msg: "Database error" });
        }
        if (!results || results.length === 0) {
          return res.status(404).json({ msg: "User not found" });
        }

        const user = results[0];

        if (user.email !== email) {
          return res
            .status(400)
            .json({ msg: "Email does not match logged in account" });
        }

        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) {
          return res.status(401).json({ msg: "Incorrect password" });
        }

        // OPTIONAL: store deletion reason in a audits table (if you want). Not implemented here.

        // 2) delete password vault entries
        db.query(
          "DELETE FROM passwords WHERE owner_id = ?",
          [ownerId],
          (err2) => {
            if (err2)
              console.warn("Could not remove password vault rows:", err2);
            // continue anyway
            // 3) select files to remove physical files
            db.query(
              "SELECT filename_stored FROM files WHERE owner_id = ?",
              [ownerId],
              (err3, fileRows) => {
                if (err3)
                  console.warn("Could not fetch files to delete:", err3);

                // remove each physical file (best-effort)
                try {
                  const uploadDir = path.join(
                    __dirname,
                    "..",
                    "uploads",
                    String(ownerId)
                  );
                  if (Array.isArray(fileRows)) {
                    fileRows.forEach((r) => {
                      if (r && r.filename_stored) {
                        const fp = path.join(uploadDir, r.filename_stored);
                        try {
                          if (fs.existsSync(fp)) fs.unlinkSync(fp);
                        } catch (e) {
                          console.warn("File unlink error:", e.message);
                        }
                      }
                    });
                  }
                  // remove user upload directory if empty (best-effort)
                  try {
                    if (fs.existsSync(uploadDir))
                      fs.rmdirSync(uploadDir, { recursive: true });
                  } catch (e) {
                    /*ignore*/
                  }
                } catch (e) {
                  console.warn("Error deleting user files from disk:", e);
                }

                // 4) delete files DB rows
                db.query(
                  "DELETE FROM files WHERE owner_id = ?",
                  [ownerId],
                  (err4) => {
                    if (err4)
                      console.warn("Could not remove files rows:", err4);

                    // 5) finally delete user row
                    db.query(
                      "DELETE FROM users WHERE id = ?",
                      [ownerId],
                      (err5, result5) => {
                        if (err5) {
                          console.error("Error deleting user row:", err5);
                          return res
                            .status(500)
                            .json({ msg: "Failed to delete account" });
                        }
                        // success
                        return res.json({
                          msg: "Account and data deleted successfully",
                        });
                      }
                    );
                  }
                );
              }
            );
          }
        );
      }
    );
  } catch (err) {
    console.error("Delete account unexpected error:", err);
    return res.status(500).json({ msg: "Server error" });
  }
});

import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve frontend (index.html and others)
app.use(express.static(path.join(__dirname, "../frontend"))); // ya jaha tera index.html hai

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
});
// ✅ Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server started on port ${PORT}`));
