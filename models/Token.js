const mongoose = require('mongoose');

const TokenSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', // Referência ao seu modelo de usuário
        required: true
    },
    telefone: {
        type: String,
        required: true,
        index: true // Melhora a velocidade da busca no banco
    },
    name: {
        type: String,
        required: true, 
        description: "Nome amigável para identificar o token (ex: Token da IA, Token do Admin)"
    },
    token: {
        type: String,
        required: true,
        unique: true
    },
    permissions: {
        canCreate: { type: Boolean, default: true },
        canDelete: { type: Boolean, default: false },
        role: { type: String, default: 'viewer' }
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    active: {
        type: Boolean,
        default: true
    }
});

module.exports = mongoose.model('Token', TokenSchema);
