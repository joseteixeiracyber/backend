const router = require('express').Router();
const { checkToken } = require('../middlewares/auth');
const Receita = require('../models/Receita');
const Despesa = require('../models/Despesa');
const Investimento = require('../models/Investimento');

// --- RECEITAS ---
router.post('/receitas', checkToken, async (req, res) => {
    try {
        const { userId, tipo, fonte, valor, data, descricao } = req.body;
        const newReceita = new Receita({
            userId, tipo, fonte, descricao,
            data: new Date(data + 'T00:00:00')
        });
        newReceita.valorExatoParaCripto = String(parseFloat(valor));
        const saved = await newReceita.save();
        res.status(201).json({ msg: 'Receita registrada!', receitaId: saved._id });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

router.get('/receitas/:userId', checkToken, async (req, res) => {
    try {
        const receitas = await Receita.find({ userId: req.params.userId }).sort({ data: -1 });
        const formatadas = receitas.map(r => ({
            id: r._id, tipo: r.tipo, fonte: r.fonte, data: r.data, valor: r.getValorExato(), descricao: r.descricao
        }));
        res.status(200).json(formatadas);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// --- DESPESAS ---
router.post('/despesas', checkToken, async (req, res) => {
    try {
        const { userId, tipo, fonte, valor, data, descricao, categoria } = req.body;
        const newDespesa = new Despesa({
            userId, tipo, fonte, categoria, descricao,
            data: new Date(data + 'T00:00:00')
        });
        newDespesa.valorExatoParaCripto = String(parseFloat(valor));
        const saved = await newDespesa.save();
        res.status(201).json({ msg: 'Despesa registrada!', despesaId: saved._id });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

router.get('/despesas/:userId', checkToken, async (req, res) => {
    try {
        const despesas = await Despesa.find({ userId: req.params.userId }).sort({ data: -1 });
        const formatadas = despesas.map(d => ({
            id: d._id, tipo: d.tipo, fonte: d.fonte, categoria: d.categoria, data: d.data, valor: d.getValorExato()
        }));
        res.status(200).json(formatadas);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// --- INVESTIMENTOS ---
router.post('/investimentos', checkToken, async (req, res) => {
    try {
        const { userId, ativo, categoria, aporte, rentabilidade, data, descricao } = req.body;
        const newInvest = new Investimento({
            userId, ativo, categoria, rentabilidade: parseFloat(rentabilidade || 0),
            data: new Date(data + 'T00:00:00'), descricao
        });
        newInvest.aporteExatoParaCripto = String(parseFloat(aporte));
        const saved = await newInvest.save();
        res.status(201).json({ msg: 'Investimento registrado!', investimentoId: saved._id });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

module.exports = router;