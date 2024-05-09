const CryptoJS = require('crypto-js');

function encryptText(plaintext){
    const salt = CryptoJS.lib.WordArray.random(128/8);
    const p = "hugo afiza key";
    const key = CryptoJS.PBKDF2(p, salt, { keySize: 512/32, iterations: 1000 });    
    const AESKey = CryptoJS.enc.Base64.stringify(key);
    const encrypted = CryptoJS.AES.encrypt(plaintext, AESKey).toString();
    return { encrypted, AESKey };
}   
module.exports = encryptText
