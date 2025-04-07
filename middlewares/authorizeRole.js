module.exports = function authorizeRole(...allowedRoles) {
    return (req, res, next) => {
      const user = req.user;
  
      if (!user || !allowedRoles.includes(user.role)) {
        return res.status(403).json({ message: "No autorizado" });
      }
  
      next();
    };
  };
// Este middleware verifica si el usuario tiene uno de los roles permitidos.
// Si no tiene el rol adecuado, se responde con un error 403 (prohibido).