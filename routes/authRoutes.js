const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Token = require('../models/Token');
const { checkToken } = require('../middlewares/auth');

const JWT_SECRET = process.env.JWT_SECRET || process.env.SECRET;

// Registro
router.post('/register', async (req, res) => {
    const { name, email, password, confirmpassword } = req.body;
    if (!name || !email || !password) return res.status(422).json({ msg: 'O nome, email e senha são obrigatórios!' });
    if (password !== confirmpassword) return res.status(422).json({ msg: 'As senhas não conferem!' });

    const userExists = await User.findOne({ email });
    if (userExists) return res.status(422).json({ msg: 'Email já está em uso!' });

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);
    const user = new User({ name, email, password: passwordHash });

    try {
        await user.save();
        res.status(201).json({ msg: 'Usuário criado com sucesso!' });
    } catch (error) {
        res.status(500).json({ msg: 'Erro ao criar usuário', error });
    }
});

// Login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(422).json({ msg: 'Email e senha são obrigatórios!' });

    const user = await User.findOne({ email });
    if (!user) return res.status(422).json({ msg: 'Usuário não encontrado!' });

    const checkPassword = await bcrypt.compare(password, user.password);
    if (!checkPassword) return res.status(422).json({ msg: 'Senha inválida!' });

    try {
        const secret = process.env.SECRET;
        const token = jwt.sign({ id: user._id }, secret, { expiresIn: '3h' });
        res.status(200).json({ msg: 'Autenticação realizada!', token, userId: user._id });
    } catch (error) {
        res.status(500).json({ msg: 'Erro ao autenticar usuário', error });
    }
});

// Tokens Estáticos para IA
router.post('/generate-static-token', async (req, res) => {
    try {
        const { userId, userName, tokenName } = req.body;
        if (!userId) return res.status(400).json({ error: "ID do usuário é obrigatório" });

        const payload = { id: userId, name: userName, permissions: { createRecords: true, isAdmin: true } };
        const token = jwt.sign(payload, JWT_SECRET);

        const newToken = new Token({
            userId,
            name: tokenName || `Token de ${userName}`,
            token: token,
            permissions: payload.permissions
        });

        await newToken.save();
        res.json({ success: true, token, message: "Token gerado com sucesso!" });
    } catch (error) {
        res.status(500).json({ error: "Erro ao gerar token" });
    }
});

router.get('/my-tokens/:id', checkToken, async (req, res) => {
    try {
        const tokens = await Token.find({ userId: req.params.id });
        res.json(tokens);
    } catch (error) {
        res.status(500).json({ error: "Erro ao buscar tokens" });
    }
});

router.delete('/token/:id', checkToken, async (req, res) => {
    try {
        await Token.findByIdAndDelete(req.params.id);
        res.json({ msg: "Token removido com sucesso!" });
    } catch (error) {
        res.status(500).json({ error: "Erro ao remover token" });
    }
});

module.exports = router;