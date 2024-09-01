const express = require("express");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const cors = require("cors");
const {
  createUser,
  verifyUser,
  verifyDecodeToken,
  getUserByEmail,
} = require("./requests");
const validateCredentials = require("./Middlewares/verifyCredentials");
const verifyToken = require("./Middlewares/verifyToken");
const app = express();
const PORT = process.env.PORT;

app.use((req, res, next) => {
    console.log(`Request Method: ${req.method}`);
    console.log(`Request URL: ${req.url}`);
    console.log(`Request Body: ${JSON.stringify(req.body)}`);
    console.log(`Request Headers: ${JSON.stringify(req.headers)}`);
    
    // Captura la respuesta final
    res.on('finish', () => {
      console.log(`Response Status: ${res.statusCode}`);
      console.log(`Response Headers: ${JSON.stringify(res.getHeaders())}`);
    });
  
    next();
  });

app.use(cors());
app.use(express.json());

app.listen(PORT, console.log("Servidor ON"));

app.post("/usuarios", validateCredentials, async (req, res) => {
  const { email, password, rol, lenguage } = req.body;
  try {
    const newUser = await createUser(email, password, rol, lenguage);
    res
      .status(201)
      .json({ message: "Usuario registrado con éxito", user: newUser });
  } catch (error) {
    res.status(500).json({ message: "Error al registrar el usuario" });
  }
});

app.post("/login", validateCredentials, async (req, res) => {
  try {
    const { email, password } = req.body;
    await verifyUser(email, password);
    const token = jwt.sign({ email }, "az_AZ", { expiresIn: "2h" });

    res.json({ token });
  } catch (error) {
    console.log("Error en /login", error);
    res.status(error.code || 500).send(error);
  }
});

app.get("/usuarios", verifyToken, async (req, res) => {
  try {
    const email = verifyDecodeToken(req.header("Authorization"));
    const usuario = await getUserByEmail(email);
console.log(usuario)
    res.json([usuario]);
  } catch (error) {
    res
      .status(error.code || 500)
      .send(error.message || "Error interno del servidor");
  }
});
