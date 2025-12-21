const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 
// Assumindo que o caminho para as funções de criptografia é o mesmo
const { encrypt, decrypt } = require('../utils/encryption'); 

const CartaoCreditoSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    nome: { // Nome do cartão (Ex: Nubank, Inter)
        type: String,
        required: true,
        trim: true,
    },
    vencimento: { // Dia do vencimento da fatura (1 a 31)
        type: Number,
        required: true,
        min: 1,
        max: 31,
    },
    juros: { // Taxa de juros rotativo em porcentagem (e.g., 14.9)
        type: Number,
        default: 0,
    },
    descricao: {
        type: String,
        trim: true,
        default: '',
    },
    
    // =======================================================
    // 🔒 CAMPOS SENSÍVEIS (CRIPTOGRAFADOS)
    // =======================================================
    
    // Limite Total do Cartão
    limiteCriptografado: {
        type: String,
    },
    limiteHash: {
        type: String,
    },

    // Fatura Atual (o valor que está sendo gasto no mês)
    faturaAtualCriptografada: {
        type: String,
    },
    faturaAtualHash: {
        type: String,
    },
    
    // Campo para armazenar parcelas ativas (pode ser um array de subdocumentos ou referências futuras)
    parcelasAtivas: [{
        compra: { type: String, required: true },
        valorTotal: { type: Number, required: true }, // Valor total da compra
        totalParcelas: { type: Number, required: true },
        parcelasRestantes: { type: Number, required: true },
        dataCompra: { type: Date, default: Date.now },
    }],

    createdAt: {
        type: Date,
        default: Date.now,
    },
});

// ==========================================
// 📌 MIDDLEWARE: Criptografia antes de salvar
// ==========================================
CartaoCreditoSchema.pre('save', async function(next) {
    // Função auxiliar para processar um campo
    const processField = async (instance, virtualName, encryptedName, hashName) => {
        if (instance.isModified(encryptedName) || instance.isNew) {
            if (instance[`_${virtualName}`]) { 
                try {
                    const valorExato = String(instance[`_${virtualName}`]);
                    // 1. Criptografa o valor exato
                    instance[encryptedName] = encrypt(valorExato);

                    // 2. Gera o hash (para busca segura ou integridade)
                    const salt = await bcrypt.genSalt(10); 
                    instance[hashName] = await bcrypt.hash(valorExato, salt);
                    
                } catch (error) {
                    console.error(`Erro na criptografia/hash do campo ${virtualName}:`, error);
                    throw new Error(`Falha na criptografia do valor do campo ${virtualName}.`);
                }
            } 
        }
    };

    // Processar Limite
    await processField(this, 'limiteExato', 'limiteCriptografado', 'limiteHash');
    
    // Processar Fatura Atual
    await processField(this, 'faturaExata', 'faturaAtualCriptografada', 'faturaAtualHash');

});

// ==========================================
// 🔓 MÉTODOS DE INSTÂNCIA: Descriptografar
// ==========================================

// Descriptografa Limite
CartaoCreditoSchema.methods.getLimiteExato = function() {
    try {
        const decryptedValue = decrypt(this.limiteCriptografado);
        return parseFloat(decryptedValue); 
    } catch (e) {
        console.error("Erro ao descriptografar limite:", e);
        return null; 
    }
};

// Descriptografa Fatura Atual
CartaoCreditoSchema.methods.getFaturaExata = function() {
    try {
        const decryptedValue = decrypt(this.faturaAtualCriptografada);
        return parseFloat(decryptedValue); 
    } catch (e) {
        console.error("Erro ao descriptografar fatura atual:", e);
        return null; 
    }
};


// ==========================================
// 🔑 PROPRIEDADES VIRTUAIS PARA ENCRIPTAR
// ==========================================

// Setter virtual para Limite
CartaoCreditoSchema.virtual('limiteExatoParaCripto').set(function(valor) {
    this._limiteExato = String(valor);
    this.markModified('limiteCriptografado'); 
});

// Setter virtual para Fatura Atual
CartaoCreditoSchema.virtual('faturaExataParaCripto').set(function(valor) {
    this._faturaExata = String(valor);
    this.markModified('faturaAtualCriptografada'); 
});


module.exports = mongoose.model('CartaoCredito', CartaoCreditoSchema);