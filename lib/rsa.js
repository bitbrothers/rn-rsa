const BigInteger = require('./jsbn');
const { CustomRNG, generateSeedFromMnemonic } = require('./rng');

// Convert a (hex) string to a BigInteger object
function parseBigInt(str, r) {
  return new BigInteger(str, r);
}

function linebrk(s, n) {
  let ret = "";
  let i = 0;
  while (i + n < s.length) {
    ret += s.substring(i, i + n) + "\n";
    i += n;
  }
  return ret + s.substring(i, s.length);
}

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a BigInteger
function pkcs1pad2(s, n, rng) {
  if (n < s.length + 11) {
    console.error("Message too long for RSA");
    return null;
  }
  let ba = [];
  let i = s.length - 1;
  while (i >= 0 && n > 0) {
    const c = s.charCodeAt(i--);
    if (c < 128) {
      ba[--n] = c;
    } else if (c > 127 && c < 2048) {
      ba[--n] = (c & 63) | 128;
      ba[--n] = (c >> 6) | 192;
    } else {
      ba[--n] = (c & 63) | 128;
      ba[--n] = ((c >> 6) & 63) | 128;
      ba[--n] = (c >> 12) | 224;
    }
  }
  ba[--n] = 0;
  const x = [];
  while (n > 2) {
    x[0] = 0;
    while (x[0] === 0) rng.nextBytes(x);
    ba[--n] = x[0];
  }
  ba[--n] = 2;
  ba[--n] = 0;
  return new BigInteger(ba);
}

// "empty" RSA key constructor
function RSAKey() {
  this.n = null; // modulus
  this.e = 0; // public exponent
  this.d = null; // private exponent
  this.p = null; // prime 1
  this.q = null; // prime 2
  this.dmp1 = null; // exponent1
  this.dmq1 = null; // exponent2
  this.coeff = null; // coefficient
}

// Return modulus and public exponent as string
RSAKey.prototype.getPublicString = function () {
  const exportObj = {
    n: this.n.toString(16),
    e: this.e.toString(16),
  };
  if (exportObj.n.length % 2 === 1) {
    exportObj.n = '0' + exportObj.n;
  }
  return JSON.stringify(exportObj);
};

RSAKey.prototype.getPrivateString = function () {
  const privateKeys = ['n', 'e', 'd', 'p', 'q', 'dmp1', 'dmq1', 'coeff'];
  const ret = {};
  privateKeys.forEach((key) => {
    ret[key] = this[key] && this[key].toString(16);
    if (key !== 'e' && ret[key].length % 2 === 1) {
      ret[key] = '0' + ret[key];
    }
  });
  return JSON.stringify(ret);
};

RSAKey.prototype.setPrivateString = function (privateStr) {
  const privateObj = JSON.parse(privateStr);
  return this.setPrivateEx(privateObj);
};

RSAKey.prototype.setPublic = function (N, E) {
  if (N && E && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N, 16);
    this.e = parseInt(E, 16);
  } else {
    console.error("Invalid RSA public key");
  }
};

RSAKey.prototype.setPublicString = function (publicStr) {
  const publicObj = JSON.parse(publicStr);
  return this.setPublic(publicObj.n, publicObj.e);
};

RSAKey.prototype.doPublic = function (x) {
  return x.modPowInt(this.e, this.n);
};

RSAKey.prototype.encrypt = function (text) {
  const m = pkcs1pad2(text, (this.n.bitLength() + 7) >> 3, new CustomRNG(generateSeedFromMnemonic('your 12-word mnemonic phrase here')));
  if (m == null) return null;
  const c = this.doPublic(m);
  if (c == null) return null;
  const h = c.toString(16);
  return (h.length & 1) === 0 ? h : "0" + h;
};

// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
function pkcs1unpad2(d, n) {
  const b = d.toByteArray();
  let i = 0;
  while (i < b.length && b[i] === 0) ++i;
  if (b.length - i !== n - 1 || b[i] !== 2) return null;
  ++i;
  while (b[i] !== 0) if (++i >= b.length) return null;
  const ret = [];
  while (++i < b.length) {
    const c = b[i] & 255;
    if (c < 128) {
      ret.push(String.fromCharCode(c));
    } else if (c > 191 && c < 224) {
      ret.push(String.fromCharCode(((c & 31) << 6) | (b[i + 1] & 63)));
      ++i;
    } else {
      ret.push(String.fromCharCode(((c & 15) << 12) | ((b[i + 1] & 63) << 6) | (b[i + 2] & 63)));
      i += 2;
    }
  }
  return ret.join('');
}

// Set the private key fields N, e, and d from hex strings
RSAKey.prototype.setPrivateEx = function (params) {
  if (params.n && params.e && params.n.length > 0 && params.e.length > 0) {
    this.n = parseBigInt(params.n, 16);
    this.e = parseInt(params.e, 16);
    this.d = parseBigInt(params.d, 16);
    this.p = parseBigInt(params.p, 16);
    this.q = parseBigInt(params.q, 16);
    this.dmp1 = parseBigInt(params.dmp1, 16);
    this.dmq1 = parseBigInt(params.dmq1, 16);
    this.coeff = parseBigInt(params.coeff, 16);
  } else {
    console.error("Invalid RSA private key");
  }
};

// Generate a new random private key B bits long, using public expt E and mnemonic
RSAKey.prototype.generate = function (B, E, mnemonic) {
  const rng = new CustomRNG(generateSeedFromMnemonic(mnemonic));
  const qs = B >> 1;
  this.e = parseInt(E, 16);
  const ee = new BigInteger(E, 16);
  for (;;) {
    for (;;) {
      this.p = new BigInteger(B - qs, 1, rng);
      if (this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) === 0 && this.p.isProbablePrime(10)) break;
    }
    for (;;) {
      this.q = new BigInteger(qs, 1, rng);
      if (this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) === 0 && this.q.isProbablePrime(10)) break;
    }
    if (this.p.compareTo(this.q) <= 0) {
      const t = this.p;
      this.p = this.q;
      this.q = t;
    }
    const p1 = this.p.subtract(BigInteger.ONE);
    const q1 = this.q.subtract(BigInteger.ONE);
    const phi = p1.multiply(q1);
    if (phi.gcd(ee).compareTo(BigInteger.ONE) === 0) {
      this.n = this.p.multiply(this.q);
      this.d = ee.modInverse(phi);
      this.dmp1 = this.d.mod(p1);
      this.dmq1 = this.d.mod(q1);
      this.coeff = this.q.modInverse(this.p);
      break;
    }
  }
};

// Perform raw private operation on "x": return x^d (mod n)
RSAKey.prototype.doPrivate = function (x) {
  if (this.p == null || this.q == null) return x.modPow(this.d, this.n);

  const xp = x.mod(this.p).modPow(this.dmp1, this.p);
  const xq = x.mod(this.q).modPow(this.dmq1, this.q);

  while (xp.compareTo(xq) < 0) xp.add(this.p);
  return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
};

// Return the PKCS#1 RSA decryption of "ctext".
RSAKey.prototype.decrypt = function (ctext) {
  const c = parseBigInt(ctext, 16);
  const m = this.doPrivate(c);
  if (m == null) return null;
  return pkcs1unpad2(m, (this.n.bitLength() + 7) >> 3);
};

module.exports = RSAKey;
