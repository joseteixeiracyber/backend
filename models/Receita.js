// models/Receita.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 
// 🔑 Importar ambas as funções de criptografia no topo
const { encrypt, decrypt } = require('../utils/encryption'); 

const ReceitaSchema = new mongoose.Schema({
    // Referência ao usuário para garantir que só ele acesse
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    tipo: {
        type: String,
        required: true,
        trim: true,
    },
    fonte: {
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
    // ==========================================
    // 🔒 VALORES SEGUROS (REQUIRED REMOVIDO PARA FLUXO CORRETO)
    // ==========================================

    // 1. Criptografado: Armazena o valor exato criptografado (IV:cipherText)
    valorCriptografado: {
        type: String,
    },

    // 2. Hash: Hash do valor (Ex: hash de '3500.00'). Útil para consultas.
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
// CORREÇÃO: Removido 'next' do argumento e do corpo da função.
// O Mongoose agora espera que esta função assíncrona termine antes de prosseguir.
ReceitaSchema.pre('save', async function() {
    
    // Se o valor exato (propriedade temporária) estiver presente
    if (this._valorExato) { 
        // 1. Criptografa o valor exato
        this.valorCriptografado = encrypt(this._valorExato);

        // 2. Gera o hash (para busca e cálculo seguro)
        const salt = await bcrypt.genSalt(10); 
        this.valorHash = await bcrypt.hash(this._valorExato, salt);
    } 
    
    // O Mongoose aguarda o fim desta função 'async' para continuar
});

// ==========================================
// 🔓 MÉTODOS DE INSTÂNCIA: Descriptografar
// ==========================================
ReceitaSchema.methods.getValorExato = function() {
    try {
        // Usa a função 'decrypt' importada no topo do arquivo
        return parseFloat(decrypt(this.valorCriptografado));
    } catch (e) {
        console.error("Erro ao descriptografar valor:", e);
        return null; 
    }
};

// ==========================================
// 🔑 PROPRIEDADE VIRTUAL PARA ENCRIPTAR
// ==========================================
// Define o setter virtual que armazena o valor em this._valorExato para o middleware
ReceitaSchema.virtual('valorExatoParaCripto').set(function(valor) {
    this._valorExato = valor;
});


module.exports = mongoose.model('Receita', ReceitaSchema);