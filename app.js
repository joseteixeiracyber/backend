require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

// Importação das Rotas
const authRoutes = require('./routes/authRoutes');
const financeiroRoutes = require('./routes/financeiroRoutes');
const cartaoRoutes = require('./routes/cartaoRoutes');

const app = express();

app.use(cors({
    origin: 'https://painel.jtmoney.cloud',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Registro de Rotas
app.use('/auth', authRoutes);
app.use('/', financeiroRoutes);
app.use('/', cartaoRoutes);

// Rota User Isclada
const User = require('./models/User');
const { checkToken } = require('./middlewares/auth');
app.get('/user/:id', checkToken, async (req, res) => {
    try {
        const user = await User.findById(req.params.id, '-password');
        if (!user) return res.status(404).json({ msg: 'Usuário não encontrado' });
        res.status(200).json(user);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// Conexão Banco
const DB_USER = process.env.DB_USER;
const DB_PASS = process.env.DB_PASS;
const connectionString = `mongodb://${decodeURIComponent(DB_USER)}:${decodeURIComponent(DB_PASS)}@ia_gestao_financeira:27017/?tls=false`;

mongoose.connect(connectionString)
    .then(() => {
        app.listen(3001, () => console.log('😁 Servidor MEY online na porta 3001'));
    })
    .catch(err => console.error("Falha na conexão DB:", err));
