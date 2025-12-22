require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken');
const cors = require('cors');

// =========================
// 📌 MODELS
// =========================
const User = require('./models/User'); 
const Receita = require('./models/Receita');
const Despesa = require('./models/Despesa');
const Investimento = require('./models/Investimento'); 
const Categoria = require('./models/Categoria');
const Emprestimo = require('./models/Emprestimo');
const CartaoCredito = require('./models/CartaoCredito');
const Token = require('./models/Token'); // 🟢 Adicionado!

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || process.env.SECRET;

// =========================
// 🔥 CORS CONFIG
// =========================
app.use(cors({
    origin: 'https://painel.jtmoney.cloud',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// =========================
// 🔒 MIDDLEWARES DE PROTEÇÃO
// =========================

// Middleware padrão (Login do Front-end)
function checkToken(req, res, next) {
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
}

// Middleware para Tokens Permanentes (API/IA)
const validateApiToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const tokenString = authHeader && authHeader.split(' ')[1];

    if (!tokenString) return res.status(401).json({ error: "Token não fornecido" });

    try {
        // Verifica se o token existe no banco e está ativo
        const storedToken = await Token.findOne({ token: tokenString, active: true });
        if (!storedToken) return res.status(401).json({ error: "Token revogado ou inexistente" });

        const decoded = jwt.verify(tokenString, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ error: "Token inválido" });
    }
};

// =========================
// 🎫 ROTAS DE TOKEN (ADMIN)
// =========================

// Gerar e Salvar Token Permanente
app.post('/auth/generate-static-token', async (req, res) => {
    try {
        const { userId, userName, tokenName } = req.body;

        if (!userId) return res.status(400).json({ error: "ID do usuário é obrigatório" });

        const payload = {
            id: userId,
            name: userName,
            permissions: { createRecords: true, isAdmin: true }
        };

        const token = jwt.sign(payload, JWT_SECRET);

        // SALVANDO NO BANCO DE DADOS
        const newToken = new Token({
            userId,
            name: tokenName || `Token de ${userName}`,
            token: token,
            permissions: payload.permissions
        });

        await newToken.save();

        res.json({
            success: true,
            token,
            message: "Token permanente gerado e salvo com sucesso!"
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Erro ao gerar token" });
    }
});

// Listar tokens de um usuário (Para o Front-end)
app.get('/auth/my-tokens/:userId', checkToken, async (req, res) => {
    try {
        const tokens = await Token.find({ userId: req.params.userId });
        res.json(tokens);
    } catch (error) {
        res.status(500).json({ error: "Erro ao buscar tokens" });
    }
});

// "Apagar" (Revogar) um token
app.delete('/auth/token/:id', checkToken, async (req, res) => {
    try {
        await Token.findByIdAndDelete(req.params.id);
        res.json({ msg: "Token removido com sucesso!" });
    } catch (error) {
        res.status(500).json({ error: "Erro ao remover token" });
    }
});
// =========================
// 🔒 ROTA PROTEGIDA / GET USER
// =========================
app.get('/user/:id', checkToken, async (req, res) => {
    const { id } = req.params;

    try {
        const user = await User.findById(id, '-password');
        if (!user) return res.status(404).json({ msg: 'Usuário não encontrado!' });

        res.status(200).json(user);
    } catch (error) {
        res.status(500).json({ msg: 'Erro ao buscar usuário', error });
    }
});

// =========================
// 🟦 REGISTRO DE USUÁRIO
// =========================
app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpassword } = req.body;

    if (!name) return res.status(422).json({ msg: 'O nome é obrigatório!' });
    if (!email) return res.status(422).json({ msg: 'O email é obrigatório!' });
    if (!password) return res.status(422).json({ msg: 'A senha é obrigatória!' });
    if (password !== confirmpassword) return res.status(422).json({ msg: 'As senhas não conferem!' });

    const userExists = await User.findOne({ email });
    if (userExists) return res.status(422).json({ msg: 'Email já está em uso!' });

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({
        name,
        email,
        password: passwordHash
    });

    try {
        await user.save();
        res.status(201).json({ msg: 'Usuário criado com sucesso!' });
    } catch (error) {
        res.status(500).json({ msg: 'Erro ao criar usuário', error });
    }
});

// =========================
// 🟩 LOGIN
// =========================
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email) return res.status(422).json({ msg: 'O email é obrigatório!' });
    if (!password) return res.status(422).json({ msg: 'A senha é obrigatória!' });

    const user = await User.findOne({ email });
    if (!user) return res.status(422).json({ msg: 'Usuário não encontrado!' });

    const checkPassword = await bcrypt.compare(password, user.password);
    if (!checkPassword) return res.status(422).json({ msg: 'Senha inválida!' });

    try {
        const secret = process.env.SECRET;

        // token expira em 3 horas
        const token = jwt.sign(
            { id: user._id },
            secret,
            { expiresIn: '3h' }
        );

        res.status(200).json({
            msg: 'Autenticação realizada com sucesso!',
            token,
            userId: user._id
        });

    } catch (error) {
        res.status(500).json({ msg: 'Erro ao autenticar usuário', error });
    }
});

// =========================
// 🟢 CRIAÇÃO DE RECEITA (PROTEGIDA)
// =========================
app.post('/receitas', checkToken, async (req, res) => {
    try {
        const { userId, tipo, fonte, valor, data, descricao } = req.body;

        if (!userId || !tipo || !fonte || !valor || !data) {
            return res.status(400).json({ msg: 'Preencha todos os campos obrigatórios.' });
        }

        const newReceita = new Receita({
            userId,
            tipo,
            fonte,
            // T00:00:00 garante o dia correto no fuso local
            data: new Date(data + 'T00:00:00'), 
            descricao
        });
        
        // Atribui o valor ao virtual APÓS a criação
        newReceita.valorExatoParaCripto = String(parseFloat(valor)); 

        const savedReceita = await newReceita.save({ runValidators: true });
        res.status(201).json({ msg: 'Receita registrada com sucesso!', receitaId: savedReceita._id });

    } catch (error) {
        console.error('Erro ao registrar receita:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ msg: error.message, error: error.message });
        }
        res.status(500).json({ msg: 'Falha no servidor ao registrar a receita.', error: error.message });
    }
});

// ==========================================================
// 🟠 EDIÇÃO DE RECEITA (PROTEGIDA) - USANDO findById + save()
// ==========================================================
app.put('/receitas/:id', checkToken, async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        // 1. Encontra o documento existente
        const receita = await Receita.findById(id);

        if (!receita) {
            return res.status(404).json({ msg: 'Receita não encontrada.' });
        }

        // 2. Aplica as atualizações manualmente
        if (updates.tipo) receita.tipo = updates.tipo;
        if (updates.fonte) receita.fonte = updates.fonte;
        if (updates.descricao) receita.descricao = updates.descricao;

        // 🔑 Tratamento do Valor: 
        if (updates.valor) {
            // Atribui o novo valor de entrada diretamente ao VIRTUAL
            receita.valorExatoParaCripto = String(parseFloat(updates.valor));
        }

        // 📅 Tratamento da Data:
        if (updates.data) {
            // Garante que a data seja salva corretamente
            receita.data = new Date(updates.data + 'T00:00:00');
        }
        
        // 3. Salva a instância atualizada, que aciona o middleware pre('save')
        const updatedReceita = await receita.save(); 

        res.status(200).json({ msg: 'Receita atualizada com sucesso!', receitaId: updatedReceita._id });
    } catch (error) {
        console.error('Erro ao atualizar receita:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ msg: error.message, error: error.message });
        }
        res.status(500).json({ msg: 'Falha no servidor ao atualizar receita.', error: error.message });
    }
});

// =========================
// 🔴 EXCLUSÃO DE RECEITA (PROTEGIDA)
// =========================
app.delete('/receitas/:id', checkToken, async (req, res) => {
    try {
        const { id } = req.params;

        const deletedReceita = await Receita.findByIdAndDelete(id);

        if (!deletedReceita) {
            return res.status(404).json({ msg: 'Receita não encontrada para exclusão.' });
        }

        res.status(200).json({ msg: 'Receita excluída com sucesso!', receitaId: deletedReceita._id });
    } catch (error) {
        console.error('Erro ao excluir receita:', error);
        res.status(500).json({ msg: 'Falha no servidor ao excluir a receita.', error: error.message });
    }
});

// =========================
// 🟣 LISTAGEM DE RECEITAS (PROTEGIDA)
// =========================
app.get('/receitas/:userId', checkToken, async (req, res) => {
    const { userId } = req.params;

    try {
        const receitas = await Receita.find({ userId }).sort({ data: -1 });

        // Descriptografa o valor antes de enviar para o cliente
        const receitasFormatadas = receitas.map(r => ({
            id: r._id,
            tipo: r.tipo,
            fonte: r.fonte,
            data: r.data,
            descricao: r.descricao,
            // 🔓 Usa o método de instância para descriptografar
            valor: r.getValorExato(), 
            createdAt: r.createdAt
        }));

        res.status(200).json(receitasFormatadas);
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: 'Erro ao buscar receitas.', error: error.message });
    }
});

// =======================================================================
// 🔴 ROTAS DE DESPESAS (PROTEGIDAS) - Usando a mesma lógica de Receitas
// =======================================================================

// 🛑 CRIAÇÃO DE DESPESA (PROTEGIDA)
app.post('/despesas', checkToken, async (req, res) => {
    try {
        // 📝 Adicionando categoria como obrigatório se o schema exigir
        const { userId, tipo, fonte, valor, data, descricao, categoria } = req.body; 

        if (!userId || !tipo || !fonte || !valor || !data || !categoria) {
            return res.status(400).json({ msg: 'Preencha todos os campos obrigatórios para a despesa: userId, tipo, fonte, valor, data e categoria.' });
        }

        const newDespesa = new Despesa({
            userId,
            tipo,
            fonte,
            categoria, // Adicionado
            // Correção de Data
            data: new Date(data + 'T00:00:00'), 
            descricao
        });

        // Passando para o virtual APÓS a criação
        newDespesa.valorExatoParaCripto = String(parseFloat(valor)); 

        const savedDespesa = await newDespesa.save({ runValidators: true });
        res.status(201).json({ msg: 'Despesa registrada com sucesso!', despesaId: savedDespesa._id });

    } catch (error) {
        console.error('Erro ao registrar despesa:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ msg: error.message, error: error.message });
        }
        res.status(500).json({ msg: 'Falha no servidor ao registrar a despesa.', error: error.message });
    }
});

// 🟠 EDIÇÃO DE DESPESA (PROTEGIDA) - Usando findById + save()
app.put('/despesas/:id', checkToken, async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        const despesa = await Despesa.findById(id);

        if (!despesa) {
            return res.status(404).json({ msg: 'Despesa não encontrada.' });
        }

        // Aplica as atualizações manualmente (garante que o virtual/middleware rode)
        if (updates.tipo) despesa.tipo = updates.tipo;
        if (updates.fonte) despesa.fonte = updates.fonte;
        if (updates.descricao) despesa.descricao = updates.descricao;
        // Tratamento da Categoria
        if (updates.categoria) despesa.categoria = updates.categoria; 

        // Tratamento do Valor:
        if (updates.valor) {
            despesa.valorExatoParaCripto = String(parseFloat(updates.valor));
        }

        // Tratamento da Data:
        if (updates.data) {
            despesa.data = new Date(updates.data + 'T00:00:00');
        }
        
        // Salva a instância atualizada, acionando o pre('save')
        const updatedDespesa = await despesa.save(); 

        res.status(200).json({ msg: 'Despesa atualizada com sucesso!', despesaId: updatedDespesa._id });
    } catch (error) {
        console.error('Erro ao atualizar despesa:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ msg: error.message, error: error.message });
        }
        res.status(500).json({ msg: 'Falha no servidor ao atualizar despesa.', error: error.message });
    }
});

// 🟡 EXCLUSÃO DE DESPESA (PROTEGIDA)
app.delete('/despesas/:id', checkToken, async (req, res) => {
    try {
        const { id } = req.params;

        const deletedDespesa = await Despesa.findByIdAndDelete(id);

        if (!deletedDespesa) {
            return res.status(404).json({ msg: 'Despesa não encontrada para exclusão.' });
        }

        res.status(200).json({ msg: 'Despesa excluída com sucesso!', despesaId: deletedDespesa._id });
    } catch (error) {
        console.error('Erro ao excluir despesa:', error);
        res.status(500).json({ msg: 'Falha no servidor ao excluir a despesa.', error: error.message });
    }
});

// 🟣 LISTAGEM DE DESPESAS (PROTEGIDA)
app.get('/despesas/:userId', checkToken, async (req, res) => {
    const { userId } = req.params;

    try {
        const despesas = await Despesa.find({ userId }).sort({ data: -1 });

        // Descriptografa o valor antes de enviar para o cliente
        const despesasFormatadas = despesas.map(d => ({
            id: d._id,
            tipo: d.tipo,
            fonte: d.fonte,
            data: d.data,
            descricao: d.descricao,
            // CORREÇÃO: Adicionar Categoria na resposta
            categoria: d.categoria, 
            valor: d.getValorExato(), // Usa o método de instância para descriptografar
            createdAt: d.createdAt
        }));

        res.status(200).json(despesasFormatadas);
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: 'Erro ao buscar despesas.', error: error.message });
    }
});

// 🟢 CRIAÇÃO DE INVESTIMENTO (PROTEGIDA)
app.post('/investimentos', checkToken, async (req, res) => {
    try {
        const { userId, ativo, categoria, aporte, rentabilidade, data, descricao } = req.body;

        if (!userId || !ativo || !categoria || !aporte || !data) {
            return res.status(400).json({ msg: 'Preencha os campos obrigatórios: userId, ativo, categoria, aporte e data.' });
        }

        const newInvestimento = new Investimento({
            userId,
            ativo,
            categoria,
            rentabilidade: parseFloat(rentabilidade || 0),
            data: new Date(data + 'T00:00:00'), 
            descricao
        });
        
        // 💡 CORREÇÃO CRÍTICA: Atribua o valor ao virtual APÓS a criação da instância.
        newInvestimento.aporteExatoParaCripto = String(parseFloat(aporte));

        const savedInvestimento = await newInvestimento.save({ runValidators: true });
        res.status(201).json({ msg: 'Investimento registrado com sucesso!', investimentoId: savedInvestimento._id });

    } catch (error) {
        console.error('Erro ao registrar investimento:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ msg: error.message, error: error.message });
        }
        res.status(500).json({ msg: 'Falha no servidor ao registrar o investimento.', error: error.message });
    }
});

// 🟠 EDIÇÃO DE INVESTIMENTO (PROTEGIDA) - USANDO findById + save()
app.put('/investimentos/:id', checkToken, async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        const investimento = await Investimento.findById(id);

        if (!investimento) {
            return res.status(404).json({ msg: 'Investimento não encontrado.' });
        }

        // Aplica as atualizações manualmente
        if (updates.ativo) investimento.ativo = updates.ativo;
        if (updates.categoria) investimento.categoria = updates.categoria;
        if (updates.descricao) investimento.descricao = updates.descricao;
        if (updates.rentabilidade !== undefined) investimento.rentabilidade = parseFloat(updates.rentabilidade);
        
        // 🔑 Tratamento do Aporte (Criptografado):
        if (updates.aporte) {
            // Atribui o novo valor de entrada diretamente ao VIRTUAL/propriedade
            investimento.aporteExatoParaCripto = String(parseFloat(updates.aporte));
        }

        // 📅 Tratamento da Data:
        if (updates.data) {
            investimento.data = new Date(updates.data + 'T00:00:00');
        }
        
        const updatedInvestimento = await investimento.save(); 

        res.status(200).json({ msg: 'Investimento atualizado com sucesso!', investimentoId: updatedInvestimento._id });
    } catch (error) {
        console.error('Erro ao atualizar investimento:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ msg: error.message, error: error.message });
        }
        res.status(500).json({ msg: 'Falha no servidor ao atualizar investimento.', error: error.message });
    }
});

// 🟡 EXCLUSÃO DE INVESTIMENTO (PROTEGIDA)
app.delete('/investimentos/:id', checkToken, async (req, res) => {
    try {
        const { id } = req.params;

        const deletedInvestimento = await Investimento.findByIdAndDelete(id);

        if (!deletedInvestimento) {
            return res.status(404).json({ msg: 'Investimento não encontrado para exclusão.' });
        }

        res.status(200).json({ msg: 'Investimento excluído com sucesso!', investimentoId: deletedInvestimento._id });
    } catch (error) {
        console.error('Erro ao excluir investimento:', error);
        res.status(500).json({ msg: 'Falha no servidor ao excluir o investimento.', error: error.message });
    }
});

// 🟣 LISTAGEM DE INVESTIMENTOS (PROTEGIDA)
app.get('/investimentos/:userId', checkToken, async (req, res) => {
    const { userId } = req.params;

    try {
        const investimentos = await Investimento.find({ userId }).sort({ data: -1 });

        // Descriptografa o aporte antes de enviar para o cliente
        const investimentosFormatados = investimentos.map(i => ({
            _id: i._id, // Usando _id para ser consistente com o Mongoose
            ativo: i.ativo,
            categoria: i.categoria,
            data: i.data,
            descricao: i.descricao,
            rentabilidade: i.rentabilidade,
            // 🔓 Usa o método de instância para descriptografar o aporte
            aporte: i.getAporteExato(), 
            createdAt: i.createdAt
        }));

        res.status(200).json(investimentosFormatados);
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: 'Erro ao buscar investimentos.', error: error.message });
    }
});


// ==========================================================
// 🏷️ ROTAS DE CATEGORIAS (NOVO)
// ==========================================================
// NOTA: As categorias precisam ser buscadas por userId para trazer as personalizadas. 

// 🟢 CRIAÇÃO DE CATEGORIA (PERSONALIZADA)
app.post('/categorias', checkToken, async (req, res) => {
    try {
        const { userId, nome, tipo } = req.body; // Tipo: 'RECEITA', 'DESPESA', 'INVESTIMENTO'

        if (!userId || !nome || !tipo) {
            return res.status(400).json({ msg: 'Preencha os campos obrigatórios: userId, nome e tipo.' });
        }
        
        // Verifica se o usuário já tem uma categoria com este nome e tipo
        const categoriaExists = await Categoria.findOne({ userId, nome, tipo });
        if (categoriaExists) {
            return res.status(400).json({ msg: `Categoria '${nome}' já existe para este tipo e usuário.` });
        }

        const newCategoria = new Categoria({
            userId,
            nome,
            tipo,
            isDefault: false, // Toda categoria criada por esta rota é personalizada
            isActive: true, // Começa como ativa
        });

        const savedCategoria = await newCategoria.save({ runValidators: true });
        res.status(201).json({ msg: 'Categoria personalizada criada com sucesso!', categoria: savedCategoria });

    } catch (error) {
        console.error('Erro ao criar categoria:', error);
        res.status(500).json({ msg: 'Falha no servidor ao criar a categoria.', error: error.message });
    }
});

// 🟠 EDIÇÃO DE CATEGORIA (APENAS PERSONALIZADA)
app.put('/categorias/:id', checkToken, async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        const categoria = await Categoria.findById(id);

        if (!categoria) {
            return res.status(404).json({ msg: 'Categoria não encontrada.' });
        }
        
        if (categoria.isDefault) {
            return res.status(403).json({ msg: 'Não é possível editar categorias padrão.' });
        }

        // Atualiza campos permitidos para edição (nome e isActive)
        if (updates.nome) categoria.nome = updates.nome;
        if (updates.isActive !== undefined) categoria.isActive = updates.isActive;
        
        const updatedCategoria = await categoria.save(); 

        res.status(200).json({ msg: 'Categoria atualizada com sucesso!', categoria: updatedCategoria });
    } catch (error) {
        console.error('Erro ao atualizar categoria:', error);
        res.status(500).json({ msg: 'Falha no servidor ao atualizar categoria.', error: error.message });
    }
});


// 🟡 EXCLUSÃO DE CATEGORIA (APENAS PERSONALIZADA)
app.delete('/categorias/:id', checkToken, async (req, res) => {
    try {
        const { id } = req.params;

        const categoria = await Categoria.findById(id);

        if (!categoria) {
            return res.status(404).json({ msg: 'Categoria não encontrada para exclusão.' });
        }
        
        if (categoria.isDefault) {
            return res.status(403).json({ msg: 'Não é possível excluir categorias padrão.' });
        }
        
        await Categoria.findByIdAndDelete(id);

        res.status(200).json({ msg: 'Categoria excluída com sucesso!' });
    } catch (error) {
        console.error('Erro ao excluir categoria:', error);
        res.status(500).json({ msg: 'Falha no servidor ao excluir a categoria.', error: error.message });
    }
});


// 🟣 LISTAGEM DE CATEGORIAS (PROTEGIDA)
app.get('/categorias/:userId', checkToken, async (req, res) => {
    const { userId } = req.params;
    const { tipo } = req.query; // Permite filtrar por tipo (opcional)

    try {
        let query = {
            $or: [
                { userId: userId, isDefault: false }, // Categorias personalizadas do usuário
                { isDefault: true, userId: null },   // Categorias padrão (sem userId)
            ]
        };
        
        if (tipo) {
            // Se o tipo for especificado, filtramos as categorias padrão E as personalizadas por esse tipo
            query = {
                $and: [
                    { $or: [{ userId: userId, isDefault: false }, { isDefault: true, userId: null }] },
                    { tipo: tipo }
                ]
            };
        }

        // Busca, ordena por tipo e nome
        const categorias = await Categoria.find(query).sort({ tipo: 1, nome: 1 });

        res.status(200).json(categorias);
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: 'Erro ao buscar categorias.', error: error.message });
    }
});
// =======================================================================
// 💸 ROTAS DE EMPRÉSTIMOS/FINANCIAMENTOS (PROTEGIDAS)
// =======================================================================

// 🟢 CRIAÇÃO DE EMPRÉSTIMO (PROTEGIDA)
app.post('/emprestimos', checkToken, async (req, res) => {
    try {
        const { userId, tipo, banco, valor, juros, parcelas, parcelasPagas, dataInicio, descricao } = req.body;

        if (!userId || !tipo || !valor || !juros || !parcelas || !dataInicio) {
            return res.status(400).json({ msg: 'Preencha os campos obrigatórios: userId, tipo, valor, juros, parcelas e dataInicio.' });
        }
        
        const numParcelasPagas = parseInt(parcelasPagas, 10) || 0;

        const newEmprestimo = new Emprestimo({
            userId,
            tipo,
            banco,
            juros: parseFloat(juros), 
            parcelas: parseInt(parcelas, 10),
            parcelasPagas: numParcelasPagas,
            dataInicio: new Date(dataInicio + 'T00:00:00'), 
            descricao
        });

        // 💡 CRÍTICO: Atribua o valor ao virtual APÓS a criação da instância.
        newEmprestimo.valorExatoParaCripto = String(parseFloat(valor));

        const savedEmprestimo = await newEmprestimo.save({ runValidators: true });
        res.status(201).json({ msg: 'Empréstimo registrado com sucesso!', emprestimoId: savedEmprestimo._id });

    } catch (error) {
        console.error('Erro ao registrar empréstimo:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ msg: error.message, error: error.message });
        }
        res.status(500).json({ msg: 'Falha no servidor ao registrar o empréstimo.', error: error.message });
    }
});

// 🟠 EDIÇÃO DE EMPRÉSTIMO (PROTEGIDA)
app.put('/emprestimos/:id', checkToken, async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        const emprestimo = await Emprestimo.findById(id);

        if (!emprestimo) {
            return res.status(404).json({ msg: 'Empréstimo não encontrado.' });
        }

        // Aplica as atualizações manualmente
        if (updates.tipo) emprestimo.tipo = updates.tipo;
        if (updates.banco) emprestimo.banco = updates.banco;
        if (updates.juros) emprestimo.juros = parseFloat(updates.juros);
        if (updates.parcelas) emprestimo.parcelas = parseInt(updates.parcelas, 10);
        if (updates.parcelasPagas !== undefined) emprestimo.parcelasPagas = parseInt(updates.parcelasPagas, 10);
        if (updates.descricao) emprestimo.descricao = updates.descricao;
        
        // 🔑 Tratamento do Valor (Criptografado):
        if (updates.valor) {
            emprestimo.valorExatoParaCripto = String(parseFloat(updates.valor));
        }

        // 📅 Tratamento da Data:
        if (updates.dataInicio) {
            emprestimo.dataInicio = new Date(updates.dataInicio + 'T00:00:00');
        }
        
        const updatedEmprestimo = await emprestimo.save(); 

        res.status(200).json({ msg: 'Empréstimo atualizado com sucesso!', emprestimoId: updatedEmprestimo._id });
    } catch (error) {
        console.error('Erro ao atualizar empréstimo:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ msg: error.message, error: error.message });
        }
        res.status(500).json({ msg: 'Falha no servidor ao atualizar empréstimo.', error: error.message });
    }
});

// 🟡 EXCLUSÃO DE EMPRÉSTIMO (PROTEGIDA)
app.delete('/emprestimos/:id', checkToken, async (req, res) => {
    try {
        const { id } = req.params;

        const deletedEmprestimo = await Emprestimo.findByIdAndDelete(id);

        if (!deletedEmprestimo) {
            return res.status(404).json({ msg: 'Empréstimo não encontrado para exclusão.' });
        }

        res.status(200).json({ msg: 'Empréstimo excluído com sucesso!', emprestimoId: deletedEmprestimo._id });
    } catch (error) {
        console.error('Erro ao excluir empréstimo:', error);
        res.status(500).json({ msg: 'Falha no servidor ao excluir o empréstimo.', error: error.message });
    }
});

// 🟣 LISTAGEM DE EMPRÉSTIMOS (PROTEGIDA)
app.get('/emprestimos/:userId', checkToken, async (req, res) => {
    const { userId } = req.params;

    try {
        const emprestimos = await Emprestimo.find({ userId }).sort({ dataInicio: -1 });

        // Descriptografa o valor antes de enviar para o cliente
        const emprestimosFormatados = emprestimos.map(e => ({
            _id: e._id, 
            tipo: e.tipo,
            banco: e.banco,
            dataInicio: e.dataInicio,
            juros: e.juros,
            parcelas: e.parcelas,
            parcelasPagas: e.parcelasPagas,
            descricao: e.descricao,
            // 🔓 Usa o método de instância para descriptografar o valor
            valor: e.getValorExato(), 
            createdAt: e.createdAt
        }));

        res.status(200).json(emprestimosFormatados);
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: 'Erro ao buscar empréstimos.', error: error.message });
    }
});
// 🟢 CRIAÇÃO DE CARTÃO DE CRÉDITO (PROTEGIDA)
app.post('/cartoes', checkToken, async (req, res) => {
    try {
        const { userId, nome, limite, faturaAtual, vencimento, juros, descricao, parcelasAtivas } = req.body;

        if (!userId || !nome || limite === undefined || vencimento === undefined) {
            return res.status(400).json({ msg: 'Preencha os campos obrigatórios: userId, nome, limite e vencimento.' });
        }
        
        const numVencimento = parseInt(vencimento, 10);
        
        // 🚨 AJUSTE DE VALIDAÇÃO: Vencimento deve ser entre 1 e 31
        if (isNaN(numVencimento) || numVencimento < 1 || numVencimento > 31) {
            return res.status(400).json({ msg: 'O dia de vencimento (vencimento) deve ser um número entre 1 e 31.' });
        }
        
        const floatLimite = parseFloat(limite);
        if (isNaN(floatLimite) || floatLimite < 0) {
             return res.status(400).json({ msg: 'O limite deve ser um valor numérico positivo válido.' });
        }

        const newCartao = new CartaoCredito({
            userId,
            nome,
            vencimento: numVencimento,
            juros: parseFloat(juros || 0), 
            descricao,
            parcelasAtivas: parcelasAtivas || [],
        });

        // 💡 CRÍTICO: Atribua o valor ao virtual APÓS a criação da instância para acionar a criptografia.
        newCartao.limiteExatoParaCripto = String(floatLimite);
        
        // Fatura atual: Garante que, se for fornecida, é um número. Se não, usa 0.
        let floatFaturaAtual = 0;
        if (faturaAtual !== undefined) {
            floatFaturaAtual = parseFloat(faturaAtual);
            if (isNaN(floatFaturaAtual)) {
                return res.status(400).json({ msg: 'Fatura atual deve ser um valor numérico válido.' });
            }
        }
        newCartao.faturaExataParaCripto = String(floatFaturaAtual);

        const savedCartao = await newCartao.save({ runValidators: true });
        res.status(201).json({ msg: 'Cartão de crédito registrado com sucesso!', cartaoId: savedCartao._id });

    } catch (error) {
        console.error('Erro ao registrar cartão de crédito:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ msg: error.message, error: error.message });
        }
        res.status(500).json({ msg: 'Falha no servidor ao registrar o cartão.', error: error.message });
    }
});

// 🟠 EDIÇÃO DE CARTÃO DE CRÉDITO (PROTEGIDA)
app.put('/cartoes/:id', checkToken, async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        const cartao = await CartaoCredito.findById(id);

        if (!cartao) {
            return res.status(404).json({ msg: 'Cartão de crédito não encontrado.' });
        }

        // Aplica as atualizações manualmente
        if (updates.nome) cartao.nome = updates.nome;
        if (updates.juros !== undefined) cartao.juros = parseFloat(updates.juros) || 0;
        
        if (updates.vencimento !== undefined) {
            const numVencimento = parseInt(updates.vencimento, 10);
            // 🚨 AJUSTE DE VALIDAÇÃO: Vencimento deve ser entre 1 e 31
            if (isNaN(numVencimento) || numVencimento < 1 || numVencimento > 31) {
                 return res.status(400).json({ msg: 'O dia de vencimento (vencimento) deve ser um número entre 1 e 31.' });
            }
            cartao.vencimento = numVencimento;
        }

        if (updates.descricao) cartao.descricao = updates.descricao;
        
        // 🔑 Tratamento do Limite (Criptografado):
        if (updates.limite !== undefined) {
            const floatLimite = parseFloat(updates.limite);
            if (isNaN(floatLimite) || floatLimite < 0) {
                 return res.status(400).json({ msg: 'O limite deve ser um valor numérico positivo válido.' });
            }
            cartao.limiteExatoParaCripto = String(floatLimite);
        }

        // 🔑 Tratamento da Fatura Atual (Criptografada):
        if (updates.faturaAtual !== undefined) {
            const floatFaturaAtual = parseFloat(updates.faturaAtual);
             if (isNaN(floatFaturaAtual)) {
                 return res.status(400).json({ msg: 'Fatura atual deve ser um valor numérico válido.' });
            }
            cartao.faturaExataParaCripto = String(floatFaturaAtual);
        }

        // Parcelas ativas
        if (updates.parcelasAtivas !== undefined) {
             cartao.parcelasAtivas = updates.parcelasAtivas;
        }
        
        const updatedCartao = await cartao.save(); 

        res.status(200).json({ msg: 'Cartão de crédito atualizado com sucesso!', cartaoId: updatedCartao._id });
    } catch (error) {
        console.error('Erro ao atualizar cartão de crédito:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ msg: error.message, error: error.message });
        }
        res.status(500).json({ msg: 'Falha no servidor ao atualizar cartão.', error: error.message });
    }
});

// 🟡 EXCLUSÃO DE CARTÃO DE CRÉDITO (PROTEGIDA)
app.delete('/cartoes/:id', checkToken, async (req, res) => {
    try {
        const { id } = req.params;

        const deletedCartao = await CartaoCredito.findByIdAndDelete(id);

        if (!deletedCartao) {
            return res.status(404).json({ msg: 'Cartão de crédito não encontrado para exclusão.' });
        }

        res.status(200).json({ msg: 'Cartão de crédito excluído com sucesso!', cartaoId: deletedCartao._id });
    } catch (error) {
        console.error('Erro ao excluir cartão de crédito:', error);
        res.status(500).json({ msg: 'Falha no servidor ao excluir o cartão.', error: error.message });
    }
});

// 🟣 LISTAGEM DE CARTÕES DE CRÉDITO (PROTEGIDA)
app.get('/cartoes/:userId', checkToken, async (req, res) => {
    const { userId } = req.params;

    try {
        // Ordena por dia de vencimento
        const cartoes = await CartaoCredito.find({ userId }).sort({ vencimento: 1 }); 

        // Descriptografa os campos de valor antes de enviar para o cliente
        const cartoesFormatados = cartoes.map(c => ({
            _id: c._id, 
            nome: c.nome,
            vencimento: c.vencimento,
            juros: c.juros,
            descricao: c.descricao,
            parcelasAtivas: c.parcelasAtivas,
            
            // 🔓 Usa os métodos de instância para descriptografar os valores
            limite: c.getLimiteExato(), 
            faturaAtual: c.getFaturaExata(),
            
            createdAt: c.createdAt
        }));

        res.status(200).json(cartoesFormatados);
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: 'Erro ao buscar cartões de crédito.', error: error.message });
    }
});
// =========================
// 🟨 CONEXÃO COM BANCO
// =========================
const DB_USER = process.env.DB_USER;
const DB_PASS = process.env.DB_PASS;
// 🛡️ Melhoria: Usar decodeURIComponent para garantir que caracteres especiais não quebrem a conexão
const connectionString = `mongodb://${decodeURIComponent(DB_USER)}:${decodeURIComponent(DB_PASS)}@ia_gestao_financeira:27017/?tls=false`;
mongoose.connect(connectionString)
    .then(() => {
        app.listen(3001, () => {
            console.log('Servidor rodando na porta 3001');
        });
        console.log('Conectado ao banco de dados');
    })
    .catch(err => console.log(err));