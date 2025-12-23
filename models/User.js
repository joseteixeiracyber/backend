const mongoose = require('mongoose');

const User = mongoose.model('User', {
    name: String,
    email: String,
    telefone: String,
    password: String,
})

module.exports = User;
