const { Pool } = require("pg");
require("dotenv").config();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  allowExitOnIdle: true,
});

const createUser = async (email, password, rol, lenguage) => {
  try {
    if (!email || !password || !rol || !lenguage) {
      throw new Error("Todos los campos son obligatorios");
    }
    const encryptedPassword = bcrypt.hashSync(password, 10);
    const consulta = "INSERT INTO usuarios values (DEFAULT, $1, $2, $3, $4)";
    const values = [email, encryptedPassword, rol, lenguage];
    const result = await pool.query(consulta, values);

    return result.rows[0];
  } catch (error) {
    console.error("Error al crear el usuario:", error);
    throw error;
  }
};

const verifyUser = async (email, password) => {
  try {
    const values = [email];
    const consulta = "SELECT * FROM usuarios WHERE email = $1";

    const {
      rows: [usuario],
      rowCount,
    } = await pool.query(consulta, values);

    const { password: encryptedPassword } = usuario;
    const passwordIsCorrect = await bcrypt.compare(password, encryptedPassword);

    if (!passwordIsCorrect || !rowCount)
      throw {
        code: 401,
        message: "No se encuentra usuario con estas credenciales",
      };
  } catch (error) {
    console.error("Error al verificar el usuario:", error);
    throw error;
  }
};

const verifyDecodeToken = (authorizationHeader) => {
  if (!authorizationHeader) {
    throw { code: 401, message: "No se proporcionó un token" };
  }
  const token = authorizationHeader.split("Bearer ")[1];
  if (!token) {
    throw { code: 401, message: "Token inválido" };
  }
  try {
    jwt.verify(token, "az_AZ");
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.email) {
      throw { code: 401, message: "Token inválido o email no presente" };
    }

    return decoded.email;
  } catch (error) {
    console.log("error al verificar o decodificar el token:", error);
    throw { code: 401, message: "Token inválido o expirado" };
  }
};

const getUserByEmail = async (email) => {
  const consulta = "SELECT * FROM usuarios WHERE email = $1";
  const values = [email];
  const {
    rows: [usuario],
    rowCount,
  } = await pool.query(consulta, values);

  if (!rowCount) {
    throw { code: 404, message: "Usuario no encontrado" };
  }
  return usuario;
};

module.exports = { createUser, verifyUser, verifyDecodeToken, getUserByEmail };
