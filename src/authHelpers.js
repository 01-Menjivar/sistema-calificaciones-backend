const crypto = require('crypto');

// Genera un salt aleatorio para cada usuario registrado
function generarSalt() {
    return crypto.randomBytes(16).toString('hex');
}

// Genera un hash de la contraseña usando el salt dado
function generarHashConSalt(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
}

// Extrae el salt del hash almacenado (si está guardado junto con el hash)
function extraerSalt(hashAlmacenado) {
    return hashAlmacenado.substring(0, 32);  // Por ejemplo, si el salt es la primera parte del hash
}

module.exports = { generarSalt, generarHashConSalt, extraerSalt };
