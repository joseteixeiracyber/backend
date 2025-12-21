// models/Categoria.js
const mongoose = require('mongoose');

const CategoriaSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null, // Null para categorias padrão
    },
    nome: {
        type: String,
        required: true,
        trim: true,
    },
    // Tipo: 'RECEITA', 'DESPESA', 'INVESTIMENTO'
    tipo: {
        type: String,
        required: true,
        enum: ['RECEITA', 'DESPESA', 'INVESTIMENTO'],
    },
    isDefault: {
        type: Boolean,
        required: true,
        default: false,
    },
    isActive: {
        type: Boolean,
        required: true,
        default: true,
    }
}, { timestamps: true });

// Adiciona um índice para garantir a unicidade de categorias
CategoriaSchema.index({ userId: 1, nome: 1, tipo: 1 }, { unique: true, partialFilterExpression: { isDefault: false } });
CategoriaSchema.index({ nome: 1, tipo: 1 }, { unique: true, partialFilterExpression: { isDefault: true, userId: null } });


const Categoria = mongoose.model('Categoria', CategoriaSchema);
module.exports = Categoria;