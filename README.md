# DataDome Encryption - Guide d'utilisation

Guide d'utilisation complet du module de chiffrement/déchiffrement DataDome.

## Utilisation

### Import du module

```javascript
const { DataDomeEncryptor, DataDomeDecryptor } = require('datadome-de-encoder');
```

---

## Chiffrement (Encryption)

### Exemple de base

```javascript
const { DataDomeEncryptor } = require('datadome-de-encoder');

// Créer l'encrypteur
const encryptor = new DataDomeEncryptor(hash, cid);

// Ajouter des données (paires clé-valeur)
encryptor.add("screenWidth", 1920);
encryptor.add("userAgent", "Mozilla/5.0...");
encryptor.add("timestamp", 1234567890);

// Générer le payload chiffré
const encrypted = encryptor.encrypt();
console.log(encrypted);
```

### Paramètres du constructeur

```javascript
new DataDomeEncryptor(hash, cid, salt, challengeType)
```

**Paramètres:**

- **`hash`** *(string, obligatoire)*  
  Hash DataDome (ex: `"D9A52CB22EA3EBADB89B9212A5EB6"`)

- **`cid`** *(string, obligatoire)*  
  Client ID DataDome

- **`salt`** *(number ou null, optionnel - défaut: `null`)*  
  Salt pour le chiffrement. Si `null`, un salt sera **calculé automatiquement** basé sur l'horodatage (`Date.now()`).  
  Pour le déchiffrement, vous devez utiliser le **même salt** que celui généré lors du chiffrement.

- **`challengeType`** *(string, optionnel - défaut: `'captcha'`)*  
  Type de challenge: `'captcha'` ou `'interstitial'`

### Types de challenges

#### 1. CAPTCHA (par défaut)

```javascript
const encryptor = new DataDomeEncryptor(
    "14D062F60A4BDE8CE8647DFC720349",
    "client_id_here",
    null,
    "captcha"  // ou omis (défaut)
);
```

**Caractéristiques:**
- Constante hash XOR: `-1748112727`
- HSV dynamique généré
- Gestion du padding base64 standard
- Utilisé pour les réponses CAPTCHA classiques

#### 2. INTERSTITIAL

```javascript
const encryptor = new DataDomeEncryptor(
    "14D062F60A4BDE8CE8647DFC720349",
    "client_id_here",
    null,
    "interstitial"
);
```

**Caractéristiques:**
- Constante hash XOR: `-883841716`
- HSV fixe: `"9E9FC74889F6"`
- Pas de gestion du padding base64
- Utilisé pour les pages interstitielles DataDome

### Changer le type de challenge dynamiquement

```javascript
const encryptor = new DataDomeEncryptor(hash, cid);

// Passer en interstitial
encryptor.setChallengeType("interstitial");

// Revenir au captcha
encryptor.setChallengeType("captcha");
```

### Méthodes de l'encrypteur

#### `add(key, value)`

Ajoute une paire clé-valeur aux données à chiffrer.

```javascript
encryptor.add("key", "value");
encryptor.add("nombre", 123);
encryptor.add("boolean", true);
encryptor.add("objet", { nested: "data" });
```

#### `encrypt()`

Génère le payload chiffré final.

```javascript
const encryptedPayload = encryptor.encrypt();
// Retourne une chaîne encodée en base64 custom
```

---

## Déchiffrement (Decryption)

### Exemple de base

```javascript
const { DataDomeDecryptor } = require('datadome-de-encoder');

// Créer le décrypteur avec les MÊMES paramètres que l'encryption
const decryptor = new DataDomeDecryptor(hash, cid, salt, challengeType);

// Déchiffrer le payload
const decrypted = decryptor.decrypt(encryptedPayload);
console.log(decrypted);
// Retourne: [["key1", "value1"], ["key2", 123], ...]
```

### Paramètres du constructeur

```javascript
new DataDomeDecryptor(hash, cid, salt, challengeType)
```

**Paramètres:**

- **`hash`** *(string, obligatoire)*  
  Hash DataDome (DOIT être identique à l'encryption)

- **`cid`** *(string, obligatoire)*  
  Client ID DataDome (DOIT être identique à l'encryption)

- **`salt`** *(number ou null, optionnel)*  
  Salt utilisé pour le chiffrement (DOIT être identique à celui de l'encryption).  
  Si l'encryption a utilisé un salt auto-généré, vous devez le récupérer via `encryptor.salt` après l'encryption.

- **`challengeType`** *(string, optionnel - défaut: `'captcha'`)*  
  Type de challenge (DOIT être identique à l'encryption)

### Attention: Correspondance des paramètres

Pour que le déchiffrement fonctionne, **TOUS** les paramètres doivent être **EXACTEMENT** les mêmes que ceux utilisés pour le chiffrement:

```javascript
// CORRECT
const encryptor = new DataDomeEncryptor(hash, cid, null, "interstitial");
const decryptor = new DataDomeDecryptor(hash, cid, null, "interstitial");

// INCORRECT - challengeType différent
const encryptor = new DataDomeEncryptor(hash, cid, null, "interstitial");
const decryptor = new DataDomeDecryptor(hash, cid, null, "captcha");
// Le déchiffrement échouera ou produira des données corrompues
```

### Exemple complet Encryption + Decryption

```javascript
const { DataDomeEncryptor, DataDomeDecryptor } = require('datadome-de-encoder');

const hash = "D9A52CB22EA3EBADB89B9212A5EB6";
const cid = "tUL4RXkyLUJxd3N2UVY4X3NHfmJkZX5zYGBmZmZ8Y1VpY1U";
const challengeType = "interstitial";

// === CHIFFREMENT ===
const encryptor = new DataDomeEncryptor(hash, cid, null, challengeType);

encryptor.add("screenWidth", 1920);
encryptor.add("screenHeight", 1080);
encryptor.add("userAgent", "Mozilla/5.0...");

const encrypted = encryptor.encrypt();
console.log("Chiffré:", encrypted);

// IMPORTANT: Récupérer le salt auto-généré si nécessaire
const saltUsed = encryptor.salt;
console.log("Salt utilisé:", saltUsed);

// === DÉCHIFFREMENT ===
// Utiliser le MÊME salt que celui généré
const decryptor = new DataDomeDecryptor(hash, cid, saltUsed, challengeType);

const decrypted = decryptor.decrypt(encrypted);
console.log("Déchiffré:", decrypted);
// [["screenWidth", 1920], ["screenHeight", 1080], ["userAgent", "Mozilla/5.0..."]]
```

---

## Exemples par type de challenge

### CAPTCHA

```javascript
const { DataDomeEncryptor, DataDomeDecryptor } = require('datadome-de-encoder');

const hash = "14D062F60A4BDE8CE8647DFC720349";
const cid = "client_identifier";

// Chiffrement
const encryptor = new DataDomeEncryptor(hash, cid, null, "captcha");
encryptor.add("captchaResponse", "xyz123");
const encrypted = encryptor.encrypt();

// Déchiffrement
const decryptor = new DataDomeDecryptor(hash, cid, null, "captcha");
const decrypted = decryptor.decrypt(encrypted);
```

### INTERSTITIAL

```javascript
const { DataDomeEncryptor, DataDomeDecryptor } = require('datadome-de-encoder');

const hash = "D9A52CB22EA3EBADB89B9212A5EB6";
const cid = "tUL4RXkyLUJxd3N2UVY4X3NHfmJkZX5zYGBmZmZ8Y1VpY1U";

// Chiffrement
const encryptor = new DataDomeEncryptor(hash, cid, null, "interstitial");
encryptor.add("pageData", "info");
const encrypted = encryptor.encrypt();

// Déchiffrement
const decryptor = new DataDomeDecryptor(hash, cid, null, "interstitial");
const decrypted = decryptor.decrypt(encrypted);
```

---

## Résumé des différences par type

**Constantes et comportements par type de challenge:**

- **captcha** (par défaut)
  - Constante Hash XOR: `-1748112727`
  - HSV: Dynamique (généré)
  - Padding Base64: Oui

- **interstitial**
  - Constante Hash XOR: `-883841716`
  - HSV: `"9E9FC74889F6"` (fixe)
  - Padding Base64: Non

---

## Notes importantes

1. **Salt auto-généré**: Si vous ne fournissez pas de salt (ou `salt=null`), il sera **calculé automatiquement** basé sur `Date.now()`. Pour déchiffrer, vous devez récupérer ce salt via `encryptor.salt` après l'encryption.

2. **Salt fixe**: Pour garantir la reproductibilité (tests, comparaisons), vous pouvez fournir un salt fixe (ex: `0`) :
   ```javascript
   const encryptor = new DataDomeEncryptor(hash, cid, 0, challengeType);
   const decryptor = new DataDomeDecryptor(hash, cid, 0, challengeType);
   ```

3. **Correspondance des paramètres**: Pour que le déchiffrement fonctionne, **TOUS** les paramètres (hash, cid, salt, challengeType) doivent être **EXACTEMENT** identiques entre l'encrypteur et le décrypteur.

4. **Hash et CID**: Ces valeurs proviennent de DataDome et doivent être extraites de la page/requête.

5. **Type de challenge**: Seulement 2 types supportés: `'captcha'` (défaut) ou `'interstitial'`.