const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
  const authHeader = req.header("Authorization");
  if (!authHeader) {
    return res.status(401).json({ message: "No se proporcionó un token" });
  }

  const token = authHeader.split("Bearer ")[1];
  if (!token) {
    return res.status(401).json({ message: "Token inválido" });
  }

  try {
    const decoded = jwt.verify(token, "az_AZ");
    req.user = decoded; // Guardar información decodificada en el objeto req
    next();
  } catch (error) {
    console.log("Error al verificar el token:", error);
    res.status(401).json({ message: "Token inválido o expirado" });
  }
};

module.exports = verifyToken;
