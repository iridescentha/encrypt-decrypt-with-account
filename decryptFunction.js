const CryptoJS = require('crypto-js');

function decryptText(ciphertext, key) {
    const decrypted = CryptoJS.AES.decrypt(ciphertext, key);
    return decrypted.toString(CryptoJS.enc.Utf8);
}

module.exports = decryptText;
