const RSAKey = require('./lib/rsa');

const mnemonic = 'praise you muffin lion enable neck grocery crumble super myself license ghost';
const rsa = new RSAKey();
rsa.generate(1024, '10001', mnemonic);

const publicKey = rsa.getPublicString();
const privateKey = rsa.getPrivateString();

console.log('Public Key:', publicKey);
console.log('Private Key:', privateKey);
console.log(publicKey);
console.log(privateKey);
rsa.setPublicString(publicKey);
var originText = 'sample String Value';
var encrypted = rsa.encrypt(originText);
console.log(encrypted);
rsa.setPrivateString(privateKey);
var decrypted = rsa.decrypt(encrypted);
console.log(decrypted);