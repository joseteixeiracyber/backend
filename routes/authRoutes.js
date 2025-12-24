const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Token = require('../models/Token');
const { checkToken } = require('../middlewares/auth');

const JWT_SECRET = process.env.JWT_SECRET || process.env.SECRET;

// Registro
router.post('/register', async (req, res) => {
    const { name, email, telefone, password, confirmpassword } = req.body;
    if (!name || !email || !telefone || !password) return res.status(422).json({ msg: 'O nome, email, telefone e senha são obrigatórios!' });
    if (password !== confirmpassword) return res.status(422).json({ msg: 'As senhas não conferem!' });

    const userExists = await User.findOne({ email });
    if (userExists) return res.status(422).json({ msg: 'Email já está em uso!' });

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);
    const user = new User({ name, email, telefone, password: passwordHash });

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
//  ROTA DE TROCA: Token Estático -> JWT de Sessão
router.post('/exchange-token', async (req, res) => {
    try {
        const { staticToken } = req.body;

        if (!staticToken) {
            return res.status(400).json({ error: "O token estático é obrigatório" });
        }

        // 1. Procura o token no banco de dados
        const storedToken = await Token.findOne({ token: staticToken, active: true });

        if (!storedToken) {
            return res.status(401).json({ error: "Token estático inválido ou revogado" });
        }

        // 2. Gera um JWT de sessão (igual ao do login)
        // Usamos o userId que está gravado no Token Estático
        const sessionToken = jwt.sign(
            { id: storedToken.userId }, 
            process.env.SECRET, 
            { expiresIn: '3h' }
        );

        // 3. Retorna o userId e o novo token de acesso
        res.status(200).json({
            msg: "Token validado com sucesso!",
            token: sessionToken,
            userId: storedToken.userId,
            telefone: storedToken.telefone 
        });

    } catch (error) {
        console.error("Erro na troca de token:", error);
        res.status(500).json({ error: "Erro interno ao validar token" });
    }
});
// Tokens Estáticos para IA
router.post('/generate-static-token', async (req, res) => {
    try {
        const { userId, userName, tokenName } = req.body;
        if (!userId) return res.status(400).json({ error: "ID do usuário é obrigatório" });

        // --- CORREÇÃO AQUI: Buscar o usuário para pegar o telefone ---
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: "Usuário não encontrado" });

        const payload = { 
            id: userId, 
            name: userName, 
            telefone: user.telefone, // Incluindo no payload do JWT se desejar
            permissions: { createRecords: true, isAdmin: true } 
        };
        
        const token = jwt.sign(payload, JWT_SECRET);

        const newToken = new Token({
            userId,
            name: tokenName || `Token de ${userName}`,
            token: token,
            telefone: user.telefone, // <--- SALVANDO O TELEFONE NO MODELO TOKEN
            permissions: payload.permissions
        });

        await newToken.save();
        res.json({ success: true, token, message: "Token gerado com sucesso!" });
    } catch (error) {
        console.error(error);
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

// Rota para o n8n buscar o token pelo número do WhatsApp
router.get('/get-token-by-phone/:telefone', async (req, res) => {
    try {
        const { telefone } = req.params;

        // 1. Limpeza rigorosa: remove tudo que não for número
        const apenasNumeros = telefone.replace(/\D/g, '');

        // 2. Busca flexível: procura o número dentro da string (caso tenha 55 ou não)
        const tokenData = await Token.findOne({ 
            telefone: { $regex: apenasNumeros }, 
            active: true 
        });

        if (!tokenData) {
            console.log("Aviso: Token não encontrado para este número.");
            return res.status(404).json({ 
                vinculado: false,
                msg: "Nenhum token encontrado." 
            });
        }

        res.json({
            vinculado: true,
            token: tokenData.token,
            userId: tokenData.userId,
            telefone: tokenData.telefone
        });
    } catch (error) {
        console.error("Erro na rota de busca:", error);
        res.status(500).json({ error: "Erro interno no servidor" });
    }
});

module.exports = router;
