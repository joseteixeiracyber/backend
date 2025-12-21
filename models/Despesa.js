const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 
// O mesmo utils/encryption será usado
const { encrypt, decrypt } = require('../utils/encryption'); 

const DespesaSchema = new mongoose.Schema({
    // Referência ao usuário
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    tipo: { // E.g., Fixo, Variável
        type: String,
        required: true,
        trim: true,
    },
    fonte: { // E.g., Cartão, Dinheiro
        type: String,
        required: true,
        trim: true,
    },
    data: {
        type: Date,
        required: true,
    },
    descricao: {
        type: String,
        trim: true,
        default: '',
    },
    // VALORES SEGUROS
    valorCriptografado: {
        type: String,
    },
    valorHash: {
        type: String,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
});

// ==========================================
// 📌 MIDDLEWARE: Criptografia antes de salvar
// ==========================================
DespesaSchema.pre('save', async function() {
    
    if (this._valorExato) { 
        // 1. Criptografa o valor exato
        this.valorCriptografado = encrypt(this._valorExato);

        // 2. Gera o hash (para busca e cálculo seguro)
        const salt = await bcrypt.genSalt(10); 
        this.valorHash = await bcrypt.hash(this._valorExato, salt);
    } 
});

// ==========================================
// 🔓 MÉTODOS DE INSTÂNCIA: Descriptografar
// ==========================================
DespesaSchema.methods.getValorExato = function() {
    try {
        return parseFloat(decrypt(this.valorCriptografado));
    } catch (e) {
        console.error("Erro ao descriptografar valor da despesa:", e);
        return null; 
    }
};

// ==========================================
// 🔑 PROPRIEDADE VIRTUAL PARA ENCRIPTAR
// ==========================================
// Define o setter virtual que armazena o valor em this._valorExato para o middleware
DespesaSchema.virtual('valorExatoParaCripto').set(function(valor) {
    this._valorExato = String(valor);
});


module.exports = mongoose.model('Despesa', DespesaSchema);