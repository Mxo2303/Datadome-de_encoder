const fs = require('fs');

/**
 * DataDomeEncryptor
 * Implémente une routine de chiffrement/obfuscation personnalisée pour les paires clé-valeur.
 * La logique de chiffrement est intentionnellement complexe et imite un générateur de payload obfusqué réel.
 */
class DataDomeEncryptor {
    /**
     * @param {string} hash - Chaîne de hash utilisée comme partie de la seed de chiffrement.
     * @param {string} cid - Identifiant client/session utilisé dans le payload.
     * @param {number|null} salt - Salt externe optionnel pour le processus de chiffrement.
     * @param {string} challengeType - Type de challenge: 'captcha' ou 'interstitial' (défaut: 'captcha')
     */
    constructor(hash, cid, salt = null, challengeType = 'captcha') {
        this.hash = hash;
        this.cid = cid;
        this.challengeType = challengeType.toLowerCase();
        
        // Définir les constantes correctes selon le type de challenge
        if (this.challengeType === 'interstitial') {
            // Constantes pour le challenge interstitial
            this._mainPrngConstant = 9959949970;
            this._hashXorConstant = -883841716; // Interstitial utilise une constante XOR hash différente
            this._cidPrngConstant = 1809053797;
            this._hsv = this._generateHsv();
        } else {
            // Constantes par défaut pour le challenge captcha
            this._mainPrngConstant = 9959949970;
            this._hashXorConstant = -1748112727;
            this._cidPrngConstant = 1809053797;
            this._hsv = this._generateHsv();
        }
        
        this._externalSalt = salt; // Stocke le salt fourni en externe
        this._initEncryptor();
    }

    /**
     * Génère une chaîne HSV pseudo-aléatoire basée sur le hash et des valeurs aléatoires.
     * Utilisée comme valeur cachée dans le processus de chiffrement.
     * @returns {string}
     */
    _generateHsv() {
        const last4 = this.hash.slice(-4);
        const randIndex = Math.floor(Math.random() * 9);
        const randHex = Math.random().toString(16).slice(2, 10).toUpperCase();
        return randHex.slice(0, randIndex) + last4 + randHex.slice(randIndex);
    }

    /**
     * Hash une chaîne en utilisant un algorithme personnalisé, retourne un entier 32-bit ou une constante de repli.
     * @param {string} str
     * @returns {number}
     */
    _customHash(str) {
        if (!str) return 1789537805;
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = (hash << 5) - hash + str.charCodeAt(i) | 0;
        }
        return hash !== 0 ? hash : 1789537805;
    }

    /**
     * Encode une valeur 6-bit en un code de caractère personnalisé pour le payload.
     * @param {number} value
     * @returns {number}
     */
    _encode6Bits(value) {
        if (value > 37) {
            return 59 + value;
        } else if (value > 11) {
            return 53 + value;
        } else if (value > 1) {
            return 46 + value;
        } else {
            return 50 * value + 45;
        }
    }

    /**
     * Fonction de mélange bit à bit pour l'état du PRNG.
     * @param {number} value
     * @returns {number}
     */
    _mixInt(value) {
        value ^= value << 13;
        value ^= value >> 17;
        return value ^ value << 5;
    }

    /**
     * Crée une fonction PRNG avec un état interne, utilisée pour l'obfuscation.
     * @param {number} seed
     * @param {number} salt
     * @returns {function(boolean): number}
     */
    _createPrng(seed, salt) {
        let state = seed, round = -1, saltState = salt, useAlt = this._useAlt;
        this._useAlt = false;
        let cache = null;
        return [function (flag) {
            let result;
            if (cache !== null) {
                result = cache;
                cache = null;
            } else {
                if (++round > 2) {
                    state = DataDomeEncryptor.prototype._mixInt(state);
                    round = 0;
                }
                result = state >> (16 - 8 * round);
                if (useAlt) {
                    result ^= --saltState;
                }
                result &= 255;
                if (flag) {
                    cache = result;
                }
            }
            return result;
        }];
    }

    /**
     * Convertit une chaîne en tableau de bytes UTF-8 et applique un XOR sur chaque byte avec le PRNG.
     * @param {string} str
     * @param {function(): number} prng
     * @returns {number[]}
     */
    _utf8Xor(str, prng) {
        let utf8Bytes = [];
        let idx = 0;
        for (let i = 0; i < str.length; i++) {
            let code = str.charCodeAt(i);
            if (code < 128) {
                utf8Bytes[idx++] = code;
            } else if (code < 2048) {
                utf8Bytes[idx++] = code >> 6 | 192;
                utf8Bytes[idx++] = 63 & code | 128;
            } else if (55296 == (64512 & code) && i + 1 < str.length && 56320 == (64512 & str.charCodeAt(i + 1))) {
                // Paire de substitution
                code = 65536 + ((1023 & code) << 10) + (1023 & str.charCodeAt(++i));
                utf8Bytes[idx++] = code >> 18 | 240;
                utf8Bytes[idx++] = code >> 12 & 63 | 128;
                utf8Bytes[idx++] = code >> 6 & 63 | 128;
                utf8Bytes[idx++] = 63 & code | 128;
            } else {
                utf8Bytes[idx++] = code >> 12 | 224;
                utf8Bytes[idx++] = code >> 6 & 63 | 128;
                utf8Bytes[idx++] = 63 & code | 128;
            }
        }
        // Applique un XOR sur chaque byte avec prng()
        for (let j = 0; j < utf8Bytes.length; j++) {
            utf8Bytes[j] ^= prng();
        }
        return utf8Bytes;
    }

    /**
     * Convertit une valeur en JSON de manière sûre, retourne undefined en cas d'erreur.
     * @param {any} value
     * @returns {string|undefined}
     */
    _safeJson(value) {
        try {
            if (typeof value === 'string') {
                // Garantit que l'échappement des chaînes est cohérent
                return JSON.stringify(value);
            }
            return JSON.stringify(value);
        } catch (e) {
            return;
        }
    }

    /**
     * Encode un tableau de bytes en une chaîne de type base64 personnalisée.
     * @param {number[]} byteArr
     * @param {number} salt
     * @param {function(number): number} encode6Bits
     * @returns {string}
     */
    _encodePayload(byteArr, salt, encode6Bits) {
        let i = 0;
        let output = [];
        let n = salt;
        // Traite chaque groupe de 3 bytes
        while (i < byteArr.length) {
            // Combine 3 bytes en un nombre de 24 bits, avec obfuscation
            let chunk = (255 & --n ^ byteArr[i++]) << 16 |
                        (255 & --n ^ byteArr[i++]) << 8  |
                        (255 & --n ^ byteArr[i++]);
            // Divise en 4 groupes de 6 bits et encode
            output.push(
                String.fromCharCode(encode6Bits((chunk >> 18) & 63)),
                String.fromCharCode(encode6Bits((chunk >> 12) & 63)),
                String.fromCharCode(encode6Bits((chunk >> 6) & 63)),
                String.fromCharCode(encode6Bits(chunk & 63))
            );
        }
        // Gère le padding si la longueur d'entrée n'est pas un multiple de 3
        let mod = byteArr.length % 3;
        if (mod) output.length -= 3 - mod;
        return output.join('');
    }

    /**
     * Initialise ou réinitialise l'état de chiffrement (PRNG, buffer, etc.).
     */
    _resetEncryptionState() {
        this._useAlt = true;
        this._prngSeed = this._mainPrngConstant ^ this._customHash(this.hash) ^ this._hashXorConstant;
        if (this._externalSalt !== null && this._externalSalt !== undefined) {
            this._salt = this._externalSalt;
        } else {
            this._salt = this._mixInt(this._mixInt((Date.now() >> 3) ^ 11027890091) * this._mainPrngConstant);
        }
        this.salt = this._salt; // Expose le salt utilisé
        this._prng = this._createPrng(this._prngSeed, this._salt)[0];
        this._buffer = [];
        this._isFirst = true;
        this._seenKeys = new Set();
        
        // Expose les valeurs de seed pour les tests/débogage (sans changer la logique de chiffrement)
        this.prngSeed = this._prngSeed;
        this.cidPrngSeed = this._cidPrngConstant ^ this._customHash(this.cid);
    }

    /**
     * Initialise le moteur de chiffrement et configure les méthodes addSignal et buildPayload.
     */
    _initEncryptor() {
        this._resetEncryptionState();
        this.addSignal = this._addSignal.bind(this);
        this.buildPayload = this._buildPayload.bind(this);
    }

    /**
     * Ajoute une paire clé-valeur au buffer, obfusquée et encodée.
     * @param {string} key
     * @param {string|number|boolean} value
     */
    _addSignal(key, value) {
        const allowedTypes = ['number', 'string', 'boolean'];
        if (typeof key === 'string' && key.length !== 0 && (!value || allowedTypes.includes(typeof value))) {
            let hsvTemp;
            const keyStr = this._safeJson(key);
            const valueStr = this._safeJson(value);
            if (key && valueStr !== undefined && key !== 'xt1') {
                const startByte = this._prng() ^ (this._buffer.length ? 44 : 123);
                this._buffer.push(startByte);
                const keyBytes = this._utf8Xor(keyStr, this._prng);
                Array.prototype.push.apply(this._buffer, keyBytes);
                const sepByte = 58 ^ this._prng();
                this._buffer.push(sepByte);
                const valueBytes = this._utf8Xor(valueStr, this._prng);
                Array.prototype.push.apply(this._buffer, valueBytes);
                if (this._isFirst) {
                    this._isFirst = false;
                    if ((typeof this._hsv === 'string' && this._hsv.length > 0) ||
                        (typeof this._hsv === 'number' && !isNaN(this._hsv))) {
                        hsvTemp = this._hsv;
                    }
                }
            }
        }
    }

    /**
     * Construit la chaîne de payload chiffrée finale pour un cid donné.
     * @param {string} cid
     * @returns {string}
     */
    _buildPayload(cid) {
        const cidPrng = this._createPrng(this._cidPrngConstant ^ this._customHash(cid), this._salt)[0];
        // Écrit le buffer avant le XOR cidPrng
        // fs.writeFileSync('debug_encrypt_buffer.json', JSON.stringify(this._buffer));
        let output = [];
        for (let i = 0; i < this._buffer.length; i++) output.push(this._buffer[i] ^ cidPrng());
        output.push(125 ^ this._prng(true) ^ cidPrng());
        const encoded = this._encodePayload(output, this._salt, this._encode6Bits.bind(this));
        return encoded;
    }

    /**
     * Ajoute une paire clé-valeur au buffer de chiffrement (méthode publique).
     * @param {string} key
     * @param {string|number|boolean} value
     */
    add(key, value) {
        this.addSignal(key, value);
    }

    /**
     * Construit le payload chiffré pour le cid actuel (méthode publique).
     * @returns {string}
     */
    encrypt() {
        return this.buildPayload(this.cid);
    }

    /**
     * Vérifie si le résultat chiffré correspond à la sortie attendue.
     * @param {string} encrypted
     * @param {string} exceptedPath
     * @returns {boolean}
     */
    static checkResult(encrypted, exceptedPath) {
        const excepted = fs.readFileSync(exceptedPath, 'utf-8');
        const isCorrect = encrypted === excepted;
        return isCorrect;
    }

    /**
     * Obtient le type de challenge actuellement utilisé
     * @returns {string}
     */
    getChallengeType() {
        return this.challengeType;
    }

    /**
     * Met à jour le type de challenge
     * @param {string} challengeType - 'captcha' ou 'interstitial'
     */
    setChallengeType(challengeType) {
        this.challengeType = challengeType.toLowerCase();
        
        // Définit les constantes correctes selon le type de challenge
        this._mainPrngConstant = 9959949970;
        this._cidPrngConstant = 1809053797;
        
        if (this.challengeType === 'interstitial') {
            this._hashXorConstant = -883841716;
        } else {
            this._hashXorConstant = -1748112727;
            this._hsv = this._generateHsv();
        }
        
        this._initEncryptor();
    }
}

// Exporte la classe DataDomeEncryptor
module.exports = { DataDomeEncryptor };

