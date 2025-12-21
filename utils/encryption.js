// utils/encryption.js
const crypto = require('crypto');
require('dotenv').config();

const ALGORITHM = 'aes-256-cbc';
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // Chave de 32 bytes (256 bits)
const IV_LENGTH = 16; // 16 bytes para AES-256-CBC

if (ENCRYPTION_KEY.length !== 32) {
    throw new Error("ENCRYPTION_KEY deve ter 32 bytes (64 caracteres hexadecimais)");
}

/**
 * 🔒 Criptografa o valor
 * @param {string} text O valor exato (Ex: '3500.00')
 * @returns {string} O valor criptografado (IV + cipher)
 */
function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    
    let encrypted = cipher.update(String(text), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Armazena o IV junto com o texto criptografado para descriptografia futura
    return iv.toString('hex') + ':' + encrypted;
}

/**
 * 🔓 Descriptografa o valor
 * @param {string} text O valor criptografado (IV:cipher)
 * @returns {string} O valor exato
 */
function decrypt(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    
    const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
}

module.exports = { encrypt, decrypt };