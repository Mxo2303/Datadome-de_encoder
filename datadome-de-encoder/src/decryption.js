/**
 * Implementation du dechiffrement DataDome
 * 
 * Ce fichier contient une implementation de dechiffrement pour le format de chiffrement personnalise de DataDome.
 * Il inverse les etapes effectuees dans encryption_rewrite.js :
 * 1. Decode la chaine base64 personnalisee
 * 2. Inverse l'etape XOR cidPrng
 * 3. Parse les entrees du buffer (paires cle-valeur)
 * 4. Retourne les donnees parsees
 */

// Creer une classe auxiliaire qui replique exactement la fonctionnalite PRNG de DataDomeEncryptor
class PRNGHelper {
    /**
     * Fonction de mixage binaire pour l'etat PRNG.
     * @param {number} value
     * @returns {number}
     */
    _mixInt(value) {
        // IMPORTANT : Ceci doit correspondre exactement a l'implementation dans DataDomeEncryptor
        // L'ordre exact des operations est important pour que la sequence corresponde
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        return value;
    }

    /**
     * Cree une fonction PRNG avec etat interne, utilisee pour l'obfuscation.
     * @param {number} seed
     * @param {number} salt
     * @param {boolean} useAlt
     * @returns {Array<Function>}
     */
    _createPrng(seed, salt, useAlt = true) {
        let state = seed, round = -1, saltState = salt;
        // Important : Dans l'implementation originale, this._useAlt est capture comme variable locale
        // puis reinitialise a false immediatement (voir encryption_rewrite.js ligne 136)
        let useAltCopy = useAlt;
        let cache = null;

        return [function (flag) {
            let result;
            if (cache !== null) {
                result = cache;
                cache = null;
            } else {
                if (++round > 2) {
                    state = PRNGHelper.prototype._mixInt(state);
                    round = 0;
                }
                result = state >> (16 - 8 * round);
                if (useAltCopy) {
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
}

// Fonction auxiliaire pour creer un PRNG
function createPrng(seed, salt, useAlt = true) {
    return new PRNGHelper()._createPrng(seed, salt, useAlt);
}

/**
 * Decode les octets UTF-8 en chaine de caracteres
 * @param {Array<number>} bytes - Octets encodes en UTF-8
 * @returns {string} - Chaine decodee
 */
function utf8Decode(bytes) {
    let str = '';
    for (let i = 0; i < bytes.length;) {
        let b = bytes[i++];
        if (b < 128) {
            str += String.fromCharCode(b);
        } else if (b >= 192 && b < 224) {
            let b2 = bytes[i++];
            str += String.fromCharCode(((b & 31) << 6) | (b2 & 63));
        } else if (b >= 224 && b < 240) {
            let b2 = bytes[i++], b3 = bytes[i++];
            str += String.fromCharCode(((b & 15) << 12) | ((b2 & 63) << 6) | (b3 & 63));
        } else if (b >= 240) {
            let b2 = bytes[i++], b3 = bytes[i++], b4 = bytes[i++];
            let codepoint = ((b & 7) << 18) | ((b2 & 63) << 12) | ((b3 & 63) << 6) | (b4 & 63);
            codepoint -= 0x10000;
            str += String.fromCharCode(0xD800 + (codepoint >> 10));
            str += String.fromCharCode(0xDC00 + (codepoint & 0x3FF));
        }
    }
    return str;
}

/**
 * Fonction de hachage personnalisee utilisee par DataDome
 * @param {string} str - Chaine d'entree a hacher
 * @returns {number} - Valeur de hachage
 */
function customHash(str) {
    if (!str) return 1789537805;
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = (hash << 5) - hash + str.charCodeAt(i) | 0;
    }
    return hash !== 0 ? hash : 1789537805;
}

/**
 * Classe de dechiffrement DataDome
 */
class DataDomeDecryptor {
    /**
     * Cree une nouvelle instance de DataDomeDecryptor
     * @param {string} hash - Valeur de hachage utilisee pour le chiffrement
     * @param {string} cid - ID client utilise pour le chiffrement
     * @param {number} salt - Valeur de salt utilisee pour le chiffrement
     * @param {string} challengeType - Type de challenge : 'captcha' ou 'interstitial' (defaut : 'captcha')
     */
    constructor(hash, cid, salt, challengeType = 'captcha') {
        this.hash = hash;
        this.cid = cid;
        this.salt = salt || 0;
        this.challengeType = challengeType.toLowerCase();

        // Definir les constantes selon le type de challenge
        this._mainPrngConstant = 9959949970;
        this._hashXorConstant = -1748112727;
        this._cidPrngConstant = 1809053797;
        if (this.challengeType === 'interstitial') {
            this._hashXorConstant = -883841716;
        }

        // Calculer les seeds pour les PRNGs
        this.prngSeed = this._mainPrngConstant ^ customHash(hash) ^ this._hashXorConstant;
        this.cidPrngSeed = this._cidPrngConstant ^ customHash(cid);

        // Creer PRNGHelper pour la creation de PRNG
        this.prngHelper = new PRNGHelper();
    }

    /**
     * Decode un caractere encode sur 6 bits selon l'encodage personnalise de DataDome
     * @param {number} charCode - Code caractere a decoder
     * @returns {number} - Valeur 6 bits decodee
     * @private
     */
    _decode6Bits(charCode) {
        if (charCode >= 97 && charCode <= 122) return charCode - 59;      // 'a'..'z' → 38..63
        if (charCode >= 65 && charCode <= 90) return charCode - 53;      // 'A'..'Z' → 12..37
        if (charCode >= 48 && charCode <= 57) return charCode - 46;      // '0'..'9' → 2..11
        if (charCode === 45) return 0;                                    // '-' → 0
        if (charCode === 95) return 1;                                    // '_' → 1
        return 0; // repli
    }

    /**
     * Decode la chaine personnalisee de type base64
     * @param {string} encoded - Chaine encodee
     * @returns {Array<number>} - Tableau d'octets decodes
     * @private
     */
    _decodeCustomBase64(encoded) {
        let bytes = [];
        let n = this.salt;

        for (let i = 0; i < encoded.length; i += 4) {
            if (i + 3 >= encoded.length) break;

            let c1 = this._decode6Bits(encoded.charCodeAt(i));
            let c2 = this._decode6Bits(encoded.charCodeAt(i + 1));
            let c3 = this._decode6Bits(encoded.charCodeAt(i + 2));
            let c4 = this._decode6Bits(encoded.charCodeAt(i + 3));

            let chunk = (c1 << 18) | (c2 << 12) | (c3 << 6) | c4;

            bytes.push(((chunk >> 16) & 255) ^ (--n & 255));
            bytes.push(((chunk >> 8) & 255) ^ (--n & 255));
            bytes.push((chunk & 255) ^ (--n & 255));
        }
        return bytes;
        if (this.challengeType === 'interstitial') {
            return bytes;
        }

        // Gerer le padding si necessaire
        let mod = encoded.length % 4;
        if (mod) {
            bytes = bytes.slice(0, bytes.length - (3 - mod));
        }

        return bytes;
    }

    /**
     * Dechiffre les donnees encodees
     * @param {string} encoded - Donnees encodees de type base64
     * @returns {Array<Array>} - Tableau de paires cle-valeur
     */
    decrypt(encoded) {
        // Etape 1 : Decoder la chaine base64 personnalisee pour obtenir le buffer XORe
        const bufferCidPrng = this._decodeCustomBase64(encoded);

        // Etape 2 : Inverser le XOR cidPrng pour obtenir le buffer original
        const cidPrng = this.prngHelper._createPrng(this.cidPrngSeed, this.salt, false)[0];
        const bufferWithMarker = bufferCidPrng.map(b => b ^ cidPrng());

        // Etape 3 : Parser le buffer pour extraire les paires cle-valeur
        return this._parseBuffer(bufferWithMarker);
    }

    /**
     * Parse le buffer pour extraire les paires cle-valeur
     * @param {Array<number>} bufferWithMarker - Buffer a parser (avec octet marqueur)
     * @returns {Array<Array>} - Tableau de paires cle-valeur
     * @private
     */
    _parseBuffer(bufferWithMarker) {
        // Le dernier octet est un marqueur, le retirer
        const buffer = bufferWithMarker.slice(0, -1);

        // Creer PRNG pour le parsing du buffer
        // Ceci doit correspondre exactement a la facon dont le processus de chiffrement cree son PRNG
        const prng = this.prngHelper._createPrng(this.prngSeed, this.salt, true)[0];

        // Dechiffrer tout le buffer pour obtenir la structure JSON brute
        const decodedBytes = [];
        for (let i = 0; i < buffer.length; i++) {
            const b = buffer[i] ^ prng();
            decodedBytes.push(b);
        }

        // Convertir en chaine pour un traitement plus facile (avec decodage UTF-8 correct)
        const jsonStr = utf8Decode(decodedBytes);

        // Maintenant parser cette chaine pour extraire les entrees
        return this._parseJsonString(jsonStr);
    }

    /**
     * Parse la chaine JSON dechiffree en paires cle-valeur
     * @param {string} jsonStr - Chaine JSON dechiffree
     * @returns {Array<Array>} - Tableau de paires cle-valeur
     * @private
     */
    _parseJsonString(jsonStr) {
        const result = [];
        let i = 0;

        // Traiter chaque caractere
        while (i < jsonStr.length) {
            try {
                // Trouver le debut d'une entree ('{' ou ',')
                if (jsonStr[i] === '{' || jsonStr[i] === ',') {
                    i++; // Ignorer le marqueur de debut

                    // Ignorer les espaces
                    while (i < jsonStr.length && /\s/.test(jsonStr[i])) i++;

                    // Chercher la cle (qui devrait etre une chaine JSON)
                    if (jsonStr[i] !== '"') {
                        i++; // Ignorer le caractere non-guillemet
                        continue;
                    }

                    i++; // Ignorer le guillemet ouvrant
                    const keyStart = i;

                    // Lire le contenu de la cle
                    while (i < jsonStr.length && jsonStr[i] !== '"') {
                        // Gerer les caracteres echappes
                        if (jsonStr[i] === '\\') {
                            i += 2; // Ignorer la sequence d'echappement
                        } else {
                            i++;
                        }
                    }

                    if (i >= jsonStr.length) break;

                    const key = jsonStr.substring(keyStart, i);
                    i++; // Ignorer le guillemet fermant

                    // Chercher le separateur (':')
                    while (i < jsonStr.length && jsonStr[i] !== ':') i++;
                    if (i >= jsonStr.length) break;
                    i++; // Ignorer le separateur

                    // Ignorer les espaces
                    while (i < jsonStr.length && /\s/.test(jsonStr[i])) i++;
                    if (i >= jsonStr.length) break;

                    // Traiter la valeur selon son type
                    let value;
                    const valueStart = i;

                    if (jsonStr[i] === '"') {
                        // Valeur chaine
                        i++; // Ignorer le guillemet ouvrant
                        let valueContent = '';
                        let escaped = false;

                        while (i < jsonStr.length) {
                            if (escaped) {
                                valueContent += jsonStr[i];
                                escaped = false;
                            } else if (jsonStr[i] === '\\') {
                                valueContent += jsonStr[i];
                                escaped = true;
                            } else if (jsonStr[i] === '"') {
                                break;
                            } else {
                                valueContent += jsonStr[i];
                            }
                            i++;
                        }

                        if (i < jsonStr.length) i++; // Ignorer le guillemet fermant
                        
                        // Essayer de parser correctement la chaine avec JSON.parse pour gerer les echappements
                        try {
                            value = JSON.parse(`"${valueContent.replace(/"/g, '\\"')}"`);
                        } catch (e) {
                            // Si le parsing echoue, utiliser la chaine brute
                            value = this._unescapeString(valueContent);
                        }
                    } else if (jsonStr[i] === '{') {
                        // Valeur objet - traitement plus complexe necessaire, mais pour l'instant extraire comme chaine
                        let nestLevel = 1;
                        i++; // Ignorer l'accolade ouvrante
                        let objectStr = '{';

                        while (i < jsonStr.length && nestLevel > 0) {
                            if (jsonStr[i] === '{') {
                                nestLevel++;
                            } else if (jsonStr[i] === '}') {
                                nestLevel--;
                            } else if (jsonStr[i] === '"') {
                                // Ignorer toute la chaine y compris les accolades qu'elle contient
                                objectStr += jsonStr[i++];
                                while (i < jsonStr.length && jsonStr[i] !== '"') {
                                    if (jsonStr[i] === '\\') {
                                        objectStr += jsonStr[i++];
                                        if (i < jsonStr.length) objectStr += jsonStr[i++];
                                    } else {
                                        objectStr += jsonStr[i++];
                                    }
                                }
                                if (i < jsonStr.length) objectStr += jsonStr[i]; // Ajouter le guillemet fermant
                            }

                            if (i < jsonStr.length) {
                                objectStr += jsonStr[i];
                                i++;
                            }
                        }

                        try {
                            value = JSON.parse(objectStr);
                        } catch (e) {
                            value = objectStr;
                        }
                    } else if (jsonStr[i] === '[') {
                        // Valeur tableau - similaire au traitement d'objet
                        let nestLevel = 1;
                        i++; // Ignorer le crochet ouvrant
                        let arrayStr = '[';

                        while (i < jsonStr.length && nestLevel > 0) {
                            if (jsonStr[i] === '[') {
                                nestLevel++;
                            } else if (jsonStr[i] === ']') {
                                nestLevel--;
                            } else if (jsonStr[i] === '"') {
                                // Ignorer toute la chaine y compris les crochets qu'elle contient
                                arrayStr += jsonStr[i++];
                                while (i < jsonStr.length && jsonStr[i] !== '"') {
                                    if (jsonStr[i] === '\\') {
                                        arrayStr += jsonStr[i++];
                                        if (i < jsonStr.length) arrayStr += jsonStr[i++];
                                    } else {
                                        arrayStr += jsonStr[i++];
                                    }
                                }
                                if (i < jsonStr.length) arrayStr += jsonStr[i]; // Ajouter le guillemet fermant
                            }

                            if (i < jsonStr.length) {
                                arrayStr += jsonStr[i];
                                i++;
                            }
                        }

                        try {
                            value = JSON.parse(arrayStr);
                        } catch (e) {
                            value = arrayStr;
                        }
                    } else if (/[0-9-]/.test(jsonStr[i])) {
                        // Valeur nombre
                        let numStr = '';
                        while (i < jsonStr.length && /[0-9.eE+-]/.test(jsonStr[i])) {
                            numStr += jsonStr[i++];
                        }
                        value = parseFloat(numStr);
                    } else if (jsonStr.substring(i, i + 4) === 'true') {
                        value = true;
                        i += 4;
                    } else if (jsonStr.substring(i, i + 5) === 'false') {
                        value = false;
                        i += 5;
                    } else if (jsonStr.substring(i, i + 4) === 'null') {
                        value = null;
                        i += 4;
                    } else {
                        // Type de valeur inconnu - ignorer simplement ce caractere
                        i++;
                        continue;
                    }
                    // Ajouter l'entree au resultat
                    result.push([this._unescapeString(key), value]);
                } else {
                    // Ignorer tout autre caractere
                    i++;
                }
            } catch (error) {
                // Si une erreur de parsing se produit, passer au caractere suivant
                console.log("Error parsing JSON", error);
                i++;
            }
        }

        return result;
    }

    /**
     * Desechappe une chaine de maniere similaire a JavaScript avec JSON.parse
     * mais sans lever d'erreurs sur les sequences d'echappement invalides
     * @param {string} str - Chaine a desechapper
     * @returns {string} - Chaine desechappee
     * @private
     */
    _unescapeString(str) {
        if (typeof str !== 'string') return str;
        
        return str.replace(/\\(.)/g, function(match, char) {
            switch (char) {
                case 'n': return '\n';
                case 'r': return '\r';
                case 't': return '\t';
                case 'b': return '\b';
                case 'f': return '\f';
                case '\\': return '\\';
                case '"': return '"';
                default: return char; // Pour les sequences \u, garder tel quel
            }
        });
    }

    /**
     * Obtient le type de challenge actuellement utilise
     * @returns {string}
     */
    getChallengeType() {
        return this.challengeType;
    }

    /**
     * Met a jour le type de challenge et recalcule les seeds PRNG
     * @param {string} challengeType - 'captcha' ou 'interstitial'
     */
    setChallengeType(challengeType) {
        this.challengeType = challengeType.toLowerCase();

        // Mettre a jour les constantes selon le type de challenge
        if (this.challengeType === 'interstitial') {
            this._mainPrngConstant = 9959949970;
            this._hashXorConstant = -883841716;
            this._cidPrngConstant = 1809053797;
        } else {
            this._mainPrngConstant = 9959949970;
            this._hashXorConstant = -1748112727;
            this._cidPrngConstant = 1809053797;
        }

        // Recalculer les seeds
        this.prngSeed = this._mainPrngConstant ^ customHash(this.hash) ^ this._hashXorConstant;
        this.cidPrngSeed = this._cidPrngConstant ^ customHash(this.cid);
    }
}

module.exports = {
    DataDomeDecryptor,
    createPrng, // Exporte pour les tests
    utf8Decode, // Exporte pour les tests
    customHash,  // Exporte pour les tests
    PRNGHelper  // Exporte pour les tests
}; 