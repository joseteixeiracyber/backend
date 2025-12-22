const router = require('express').Router();
const { checkToken } = require('../middlewares/auth');
const CartaoCredito = require('../models/CartaoCredito');
const Emprestimo = require('../models/Emprestimo');
const Categoria = require('../models/Categoria');

// --- CARTÕES DE CRÉDITO ---
router.post('/cartoes', checkToken, async (req, res) => {
    try {
        const { userId, nome, limite, faturaAtual, vencimento, juros, descricao, parcelasAtivas } = req.body;
        const numVencimento = parseInt(vencimento, 10);
        if (numVencimento < 1 || numVencimento > 31) return res.status(400).json({ msg: 'Vencimento inválido (1-31).' });

        const newCartao = new CartaoCredito({
            userId, nome, vencimento: numVencimento, juros: parseFloat(juros || 0), descricao,
            parcelasAtivas: parcelasAtivas || []
        });
        newCartao.limiteExatoParaCripto = String(parseFloat(limite));
        newCartao.faturaExataParaCripto = String(parseFloat(faturaAtual || 0));

        const saved = await newCartao.save();
        res.status(201).json({ msg: 'Cartão criado!', cartaoId: saved._id });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

router.get('/cartoes/:userId', checkToken, async (req, res) => {
    try {
        const cartoes = await CartaoCredito.find({ userId: req.params.userId }).sort({ vencimento: 1 });
        const formatados = cartoes.map(c => ({
            id: c._id, nome: c.nome, vencimento: c.vencimento, limite: c.getLimiteExato(), fatura: c.getFaturaExata()
        }));
        res.json(formatados);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// --- EMPRÉSTIMOS ---
router.post('/emprestimos', checkToken, async (req, res) => {
    try {
        const { userId, tipo, banco, valor, juros, parcelas, parcelasPagas, dataInicio, descricao } = req.body;
        const newEmprestimo = new Emprestimo({
            userId, tipo, banco, juros: parseFloat(juros), parcelas: parseInt(parcelas),
            parcelasPagas: parseInt(parcelasPagas || 0), dataInicio: new Date(dataInicio + 'T00:00:00'), descricao
        });
        newEmprestimo.valorExatoParaCripto = String(parseFloat(valor));
        const saved = await newEmprestimo.save();
        res.status(201).json({ msg: 'Empréstimo registrado!', emprestimoId: saved._id });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// --- CATEGORIAS ---
router.get('/categorias/:userId', checkToken, async (req, res) => {
    const { userId } = req.params;
    try {
        const categorias = await Categoria.find({
            $or: [{ userId: userId, isDefault: false }, { isDefault: true, userId: null }]
        }).sort({ nome: 1 });
        res.json(categorias);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

module.exports = router;