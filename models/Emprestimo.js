const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 
const { encrypt, decrypt } = require('../utils/encryption'); 

const EmprestimoSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    tipo: { // Ex: Financiamento Imobiliário, Pessoal, Automóvel
        type: String,
        required: true,
        trim: true,
    },
    banco: { 
        type: String,
        trim: true,
        default: 'N/A',
    },
    dataInicio: {
        type: Date,
        required: true,
    },
    juros: { // Taxa de juros mensal em porcentagem (e.g., 0.8)
        type: Number,
        required: true,
    },
    parcelas: { // Total de parcelas
        type: Number,
        required: true,
    },
    parcelasPagas: { // Quantas parcelas foram pagas
        type: Number,
        required: true,
        default: 0,
    },
    descricao: {
        type: String,
        trim: true,
        default: '',
    },
    
    // ==========================================
    // 🔒 VALOR TOTAL DO EMPRÉSTIMO (CRIPTOGRAFADO)
    // ==========================================
    valorCriptografado: {
        type: String,
        // NÃO é required aqui para evitar conflito com o pre('save')
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
EmprestimoSchema.pre('save', async function() {
    
    if (this.isModified('valorCriptografado') || this.isNew) {
        
        if (this._valorExato) { 
            
            try {
                // 1. Criptografa o valor exato
                this.valorCriptografado = encrypt(this._valorExato);

                // 2. Gera o hash (para busca segura)
                const salt = await bcrypt.genSalt(10); 
                this.valorHash = await bcrypt.hash(this._valorExato, salt);
                
            } catch (error) {
                console.error("Erro na criptografia/hash do valor do empréstimo:", error);
                throw new Error("Falha na criptografia do valor do empréstimo.");
            }
        } 
    } 
});

// ==========================================
// 🔓 MÉTODOS DE INSTÂNCIA: Descriptografar
// ==========================================
EmprestimoSchema.methods.getValorExato = function() {
    try {
        const decryptedValue = decrypt(this.valorCriptografado);
        return parseFloat(decryptedValue); 
    } catch (e) {
        console.error("Erro ao descriptografar valor do empréstimo:", e);
        return null; 
    }
};

// ==========================================
// 🔑 PROPRIEDADE VIRTUAL PARA ENCRIPTAR
// ==========================================
// Define o setter virtual que armazena o valor em this._valorExato para o middleware
EmprestimoSchema.virtual('valorExatoParaCripto').set(function(valor) {
    this._valorExato = String(valor);
    // CRÍTICO: Marca o campo real como modificado para acionar o pre('save')
    this.markModified('valorCriptografado'); 
});


module.exports = mongoose.model('Emprestimo', EmprestimoSchema);