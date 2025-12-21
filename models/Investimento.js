// models/Investimento.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 
// 🔑 Importar ambas as funções de criptografia
const { encrypt, decrypt } = require('../utils/encryption'); 

const InvestimentoSchema = new mongoose.Schema({
    // ... (campos existentes)
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    ativo: {
        type: String,
        required: true,
        trim: true,
    },
    categoria: {
        type: String,
        required: true,
        trim: true,
    },
    rentabilidade: {
        type: Number,
        required: false,
        default: 0,
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
    // 🔒 VALORES SEGUROS
    // ==========================================

    aporteCriptografado: {
        type: String,
    },

    aporteHash: {
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
// Usando 'next' e definindo como ASYNC para garantir a espera pelo bcrypt
InvestimentoSchema.pre('save', async function(next) {
    
    // ⚠️ VERIFICAR SE O CAMPO REAL 'aporteCriptografado' FOI MARCADO COMO MODIFICADO
    if (this.isModified('aporteCriptografado') || this.isNew) {
        
        // Verifica se a propriedade temporária foi preenchida pelo Virtual Setter
        if (this._aporteExato) { 
            
            try {
                // 1. Criptografa o valor exato
                this.aporteCriptografado = encrypt(this._aporteExato);

                // 2. Gera o hash (para busca segura)
                const salt = await bcrypt.genSalt(10); 
                this.aporteHash = await bcrypt.hash(this._aporteExato, salt);
                
            } catch (error) {
                // Se houver qualquer erro na criptografia, passa para o próximo middleware/save
                // e garante que o Mongoose não continue sem os campos preenchidos.
                console.error("Erro na criptografia/hash do aporte:", error);
                return next(new Error("Falha na criptografia do aporte."));
            }
        } 
        // Se isModified for true, mas _aporteExato for undefined, algo está errado na rota,
        // mas como o campo é 'required', o Mongoose fará a validação logo após.
    } 
   
});

// ==========================================
// 🔓 MÉTODOS DE INSTÂNCIA: Descriptografar
// ==========================================
InvestimentoSchema.methods.getAporteExato = function() {
    try {
        const decryptedValue = decrypt(this.aporteCriptografado);
        return parseFloat(decryptedValue); 
    } catch (e) {
        console.error("Erro ao descriptografar aporte:", e);
        return null; 
    }
};

// ==========================================
// 🔑 PROPRIEDADE VIRTUAL PARA ENCRIPTAR
// ==========================================
InvestimentoSchema.virtual('aporteExatoParaCripto').set(function(aporte) {
    this._aporteExato = aporte;
    // 💡 CORREÇÃO CRÍTICA: Marca o campo real como modificado.
    // Isso é essencial para que o pre('save') execute a lógica de criptografia.
    this.markModified('aporteCriptografado'); 
});


module.exports = mongoose.model('Investimento', InvestimentoSchema);