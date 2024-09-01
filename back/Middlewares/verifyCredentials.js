const validateCredentials = (req, res, next) => {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "Email y password son requeridos" });
    }
    next();
  };
  
  module.exports = validateCredentials;
  