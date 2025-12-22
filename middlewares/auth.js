const jwt = require('jsonwebtoken');
const Token = require('../models/Token');

const JWT_SECRET = process.env.JWT_SECRET || process.env.SECRET;

const checkToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ msg: 'Acesso negado!' });

    try {
        const secret = process.env.SECRET;
        const decoded = jwt.verify(token, secret);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ msg: 'Token inválido ou expirado!' });
    }
};

const validateApiToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const tokenString = authHeader && authHeader.split(' ')[1];
    if (!tokenString) return res.status(401).json({ error: "Token não fornecido" });

    try {
        const storedToken = await Token.findOne({ token: tokenString, active: true });
        if (!storedToken) return res.status(401).json({ error: "Token revogado ou inexistente" });
        const decoded = jwt.verify(tokenString, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ error: "Token inválido" });
    }
};

module.exports = { checkToken, validateApiToken };