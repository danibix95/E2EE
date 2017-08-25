"use strict";

const base64 = require("base64-js");

// keys container
const userPublicKeys = new WeakMap(); // only contain one at time (max 1 instance of EncryptionLayer)
const userPrivateKeys = new WeakMap();
const commonKeys = new WeakMap(); // SBOX : key

// WeakMap use weak reference, so if a SBox is deleted, also the keys are deleted.

// private object
let encryptionObject = null;
let protectKey = null;

// settings
const tagLength = 128;
const AESKeyLength = 256;
const RSAKeyLength = 2048;
const hashFunction = "SHA-256";
const pubExp = new Uint8Array([0x01, 0x00, 0x01]); //65537

class EncryptionLayer {
  constructor() {
    // every time a new object is created, old object and its keys are removed
    userPublicKeys.delete(encryptionObject);
    userPrivateKeys.delete(encryptionObject);
    encryptionObject = this;
  }

  /** Initialize the encryption layer generating a new asymmetric keys pair. If public and private key are provided (pk and sk)
   *  then it will import the keys into the system, otherwise it will generate a new keys pair.
   *
   * @param password      {string}    A user password (different from Chino password).
   *                                  This will never be stored, so each user mustn't forget own.
   * @param info          {Object}    optional information used for working with keys
   * @param storeLocally  {boolean}   select if the protect key (used to wrap private key)
   *                                  have to be saved into browser session storage (if supported).
   *                                  Default is false.
   * @return {Promise.<Object>}
   */
  initEncLayer(password, info = {}, storeLocally = false) {
    return getSKWrapper(password, info, storeLocally)
        .then((protectKey) => generateKeyPair())
        .then((cryptoKey) => {
          // save keys in memory
          // userPublicKeys.set(encryptionObject, cryptoKey.publicKey);
          // userPrivateKeys.set(encryptionObject, cryptoKey.privateKey);

          return Promise.all([
            exportPK(cryptoKey.publicKey),
            exportSK(cryptoKey.privateKey, protectKey)
          ])
        })
        .then((keys) => ({
          pk : keys[0],
          sk : keys[1]
        }))
        .catch((err) => {
          throw new Error(`Impossible to initialize encryption layer:\n${err}`);
        });
  }

  /** Start the encryption layer.
   *
   * @param password      {string}    A user password (different from Chino password).
   *                                  This will never be stored, so each user mustn't forget own.
   * @param pk            {string|null}    the base64 encoded public key
   * @param sk            {string|null}    the base64 encoded private key
   * @param info          {Object}    optional information used for working with keys
   * @param storeLocally  {boolean}   select if the protect key (used to wrap private key)
   *                                  have to be saved into browser session storage (if supported).
   *                                  Default is false.
   * @return {Promise.<null>}
   */
  startEncLayer(password, pk, sk, info = {}, storeLocally = false) {
    return getSKWrapper(password, info, storeLocally)
        .then((protectKey) => {
          if (pk && sk) {
            return Promise.all([
                importPK(pk),
                importSK(sk, protectKey)
            ])
          }
          else {
            throw new Error(`Impossible to start encryption layer, because some key is missing.`);
          }
        })
        .then(() => null)   // don't return anything because keys must kept secret
        .catch((err) => {
          throw new Error(`Impossible to start encryption layer:\n${err}`);
        });
  }

  /** Test common key existence for given SBox
   *
   * @param sbox   {SBox}    The selected SBox object
   * @return    {boolean}    Return true if the exists, otherwise false.
   */
  static hasCommonKey(sbox) {
    return commonKeys.get(sbox) ? true : false;
  }

  /** Wrap key given key and return the result as a base64 encoded string
   *
   * @param sbox    {SBox}        The SBox object bound to the wrapped key
   * @param pk      {string|null} An optional public key
   * @return {Promise.<string>}   Return a Promise of a CryptoKey wrapped
   *                              and encoded as a base64 string.
   */
  static wrapKey(sbox, pk = null) {
    const runWrapping = (PK) =>
        crypto.subtle.wrapKey(
            "raw",
            ck,
            /* by default use own PK, otherwise use the provided one
            -> this is used when it is necessary to share the wrapped key */
            PK,
            {
              name: "RSA-OAEP",
              hash: {name: hashFunction},
            }
        )
        .then((key) => base64.fromByteArray(new Uint8Array(key)))
        .catch((err) => { throw new Error(`Impossible to wrap the key:\n${err}`) });

    const ck = commonKeys.get(sbox); // get common key bound to the sbox

    if(!ck) throw new Error("Impossible to wrap a key that you don't have generated or you don't own.");

    if (pk) {
      // use provided publik key
      return crypto.subtle.importKey(
          "jwk",
          JSON.parse(Buffer.from(pk, "base64")),
          {
            name: "RSA-OAEP",
            hash: {name: hashFunction},
          },
          false,
          ["wrapKey"]
      )
      .then((pkey) => runWrapping(pkey));
    }
    else {
      // use user public key
      return runWrapping(userPublicKeys.get(encryptionObject));
    }

  }

  /** Unwrap the given key and save it with the corresponding sbox
   *
   * @param sbox        {SBox}    The SBox object bound to the wrapped key
   * @param wrappedKey  {String}  A base64 encoded wrapped crypto key
   * @return {Promise.<null>}
   */
  static unwrapKey(sbox, wrappedKey) {
    let ck = commonKeys.get(sbox);
    // skip the unwrapping if it still exists
    if (!ck) {
      return crypto.subtle.unwrapKey(
        "raw",
        new Uint8Array(base64.toByteArray(wrappedKey)),
        userPrivateKeys.get(encryptionObject),
        {
          name: "RSA-OAEP",
          modulusLength: RSAKeyLength,
          publicExponent: pubExp,
          hash: {name: hashFunction},
        },
        {
          name: "AES-GCM",
          length: AESKeyLength
        },
        false,
        ["encrypt", "decrypt"]
      )
        .then((key) => { commonKeys.set(sbox, key); return null })
        .catch((err) => { throw new Error(`Impossible to unwrap the key:\n${err}`) });
    }
  }

  /** Generate a new CryptoKey for symmetric key algorithm
   *
   * @param sbox    {SBox}  The SBox object that will be bond to the key
   * @return {Promise.<CryptoKey>}
   *                        A Promise that returns the corresponding CryptoKey object
   */
  static generateCommonKey(sbox) {
    return crypto.subtle.generateKey(
        {
          name: "AES-GCM",
          length: AESKeyLength
        },
        true,
        ["encrypt", "decrypt"]
    )
        // save in memory generated key
        .then((key) => { commonKeys.set(sbox, key); return null})
        .catch((err) => { throw new Error(`Error generating new symmetric key:\n${err}`) });
  }

  /** Encrypt data with provided symmetric key
   *  and return a base64 encoded cipher text
   *
   * @param ckey      {CryptoKey} The symmetric key (common key)
   * @param data      {Object}    Data to be encrypted
   * @param timestamp {number}    Data creation UTC timestamp as milliseconds from January 1, 1970
   * @param AD        {Object|string|number}    Optional additional data used for encrypting algorithm
   * @return {Promise.<String>}
   *            Return a base64 encoded string that represent the cipher text
   */
  static encrypt(sbox, data, timestamp, AD = "") {
    return timestampHash(timestamp)
        .then((ts) =>
            crypto.subtle.encrypt(
              {
                name: "AES-GCM",
                iv: ts,
                additionalData: new TextEncoder().encode(AD),
                tagLength: tagLength,
              },
              commonKeys.get(sbox),
              Buffer.from(JSON.stringify(data))  // encode data to get a node buffer that can be decoded later
            )
        )
        .then((encrypted) => base64.fromByteArray(new Uint8Array(encrypted)))
        .catch((err) => {
          throw new Error(`Error encrypting message with symmetric key:\n${err}`);
        });
  }

  /** Decrypt given cipher text with provided symmetric key
   *  and return a JS object as plaintext
   *
   * @param ckey      {CryptoKey} The symmetric key (common key)
   * @param cipher    {Object}    Base64 encoded string that represent the cipher text to be decrypted
   * @param timestamp {number}    Data creation UTC timestamp as milliseconds from January 1, 1970
   * @param AD        {Object|string|number}    Optional additional data used for encrypting algorithm
   * @return {Promise.<String>}
   *            Return a JS object as plaintext
   */
  static decrypt(sbox, cipher, timestamp, AD = "") {
    return timestampHash(timestamp)
        .then((ts) =>
            crypto.subtle.decrypt(
                {
                  name: "AES-GCM",
                  iv: ts,
                  additionalData: new TextEncoder().encode(AD),
                  tagLength: tagLength
                },
                commonKeys.get(sbox),
                base64.toByteArray(cipher)
            )
        )
        .then((plaintext) => JSON.parse(Buffer.from(plaintext)))  // convert to node buffer before to get the object
        .catch((error) => { throw new Error(`Impossible to decrypt ciphertext:\n${error}`) });
  }

  /** Encrypt data with provided symmetric key
   *  and return a cipher text as a byte array
   *
   * @param ckey      {CryptoKey} The symmetric key (common key)
   * @param data      {Object}    Data to be encrypted
   * @param timestamp {number}    Data creation UTC timestamp as milliseconds from January 1, 1970
   * @param AD        {Object|string|number}    Optional additional data used for encrypting algorithm
   * @return {Promise.<Uint8Array>}
   *            Return the cipher text as an array of bytes
   */
  static encryptFile(sbox, file, AD = "") {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    return crypto.subtle.encrypt(
            {
              name: "AES-GCM",
              iv: iv,
              additionalData: new TextEncoder().encode(AD),
              tagLength: tagLength,
            },
            commonKeys.get(sbox),
            file  // encode data to get a node buffer that can be decoded later
        )
        .then((encrypted) => ({cipher: new Uint8Array(encrypted), iv: base64.fromByteArray(iv)}))
        .catch((err) => {
          throw new Error(`Error encrypting message with symmetric key:\n${err}`);
        });
  }

  /** Decrypt given cipher text with provided symmetric key
   *  and return a JS object as plaintext
   *
   * @param sbox
   * @param cipher    {Object}    Base64 encoded string that represent the cipher text to be decrypted
   * @param iv
   * @param AD        {Object|string|number}    Optional additional data used for encrypting algorithm
   * @return {Promise.<ArrayBuffer>}
   *            Return an ArrayBuffer from which can be constructed a JS File object
   */
  static decryptFile(sbox, cipher, iv, AD = "") {
    return crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv: iv,
              additionalData: new TextEncoder().encode(AD),
              tagLength: tagLength
            },
            commonKeys.get(sbox),
            cipher
        )
        .then((plaintext) => plaintext)
        .catch((error) => { throw new Error(`Impossible to decrypt ciphertext:\n${error}`) });
  }
}

module.exports = EncryptionLayer;

/* ======================== */
/* Module Private Functions */
/* ======================== */

/** Generate (or retrieve) the user's key used to wrap the user's private key.
 *
 * @param password      {string}    A user password (different from Chino password).
 *                                  This will never be stored, so each user mustn't forget own.
 * @param info          {Object}    Optional information used for working with keys
 * @param storeLocally  {boolean}   Select if the protect key (used to wrap private key)
 *                                  have to be saved into browser session storage (if supported).
 *                                  Default is false.
 * @return {Promise.<CryptoKey>}    Return a Promise of receiving a CryptoKey.
 * @ignore
 */
function getSKWrapper(password, info = {}, storeLocally = false) {
  // check if it's already been generated and stored locally
  if (storeLocally && window.sessionStorage) {
    protectKey = sessionStorage.getItem("protectSK");
  }

  // directly return the key saved in memory if it has already been generated
  if (protectKey) return Promise.resolve(protectKey);

  let keydata = new TextEncoder().encode(password);
  let keyHash = null;

  return H(keydata)
      .then((hash) => {
        keyHash = hash; // save the hash for later
        return crypto.subtle.importKey(
            "raw",
            keydata,
            { name: "HKDF" },
            false,
            ["deriveKey"]
        )
      })
      .then((ikey) => crypto.subtle.deriveKey(
          {
            name: "HKDF",
            info: new TextEncoder().encode(info),
            salt: keyHash,
            hash: {name: hashFunction},
          },
          ikey,
          {
            name: "AES-GCM",
            length: AESKeyLength,
          },
          false,
          ["wrapKey", "unwrapKey"]
      ))
      .then((key) => {
        // save key in memory, so it's not necessary to recompute
        protectKey = key;

        // if required save locally the key used for encrypting private key
        if (storeLocally && window.sessionStorage) {
          sessionStorage.setItem("protectSK", key);
        }

        return key;
      })
      .catch((error) => { throw new Error(`Impossible to derive a key:\n${error}`)})
}

/** Return a CryptoKeys container for a new public-private keys pair.
 *
 * @return {Promise.<CryptoKey>} The container of public-private keys
 * @ignore
 */
function generateKeyPair() {
  return crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: RSAKeyLength,
        publicExponent: pubExp,
        hash: {name: hashFunction},
      },
      true,
      ["wrapKey", "unwrapKey"]
  )
}

/** Import the given wrapped private key into the system.
 *
 * @param SK          {string}    A base64 encoded wrapped private key
 * @param protectKey  {CryptoKey} The key used to wrap the private key previously
 * @return {Promise.<undefined>}  Return a Promise that notify when the importing
 *                                process is completed and successfully.
 * @ignore
 */
function importSK(SK, protectKey){
  let keydata = JSON.parse(Buffer.from(SK, "base64"))
  let rndValues = new Uint8Array(keydata.randomValues);

  return crypto.subtle.unwrapKey(
      "jwk",
      new Uint8Array(keydata.privateKey),
      protectKey,
      {   //these are the wrapping key's algorithm options
        name: "AES-GCM",
        iv: rndValues,
        additionalData: rndValues.slice(0,8).reverse(),
        tagLength: tagLength
      },
      { // what kind of key will be used
        name: "RSA-OAEP",
        modulusLength: RSAKeyLength,
        publicExponent: pubExp,
        hash: {name: hashFunction},
      },
      false,
      ["unwrapKey"]
  )
  .then((privateKey) => { userPrivateKeys.set(encryptionObject, privateKey); return true })
  .catch((error) => { throw new Error(`Error importing private key:\n${error}`) });
}

/** Export and wrap the given private key as a base64 encoded string
 *
 * @param SK            {CryptoKey} The private key
 * @param protectKey    {CryptoKey} The key to be used for wrapping the private key
 * @return {Promise.<string>} Return a Promise of the exported private key
 * @ignore
 */
function exportSK(SK, protectKey) {
  let randomValues = crypto.getRandomValues(new Uint8Array(12));
  return crypto.subtle.wrapKey(
          "jwk",
          SK,
          protectKey,
          {
            name: "AES-GCM",
            iv: randomValues,
            additionalData: randomValues.slice(0,8).reverse(),  // use a slice of previous random values
            tagLength: tagLength
          }
      )
      .then((privateKey) =>
          Buffer.from(
            JSON.stringify({
              privateKey : Array.from(new Uint8Array(privateKey)),
              randomValues : Array.from(randomValues)
            })
          ).toString("base64")
      )
      .catch((error) => { throw new Error(`Error exporting private key:\n${error}`) });
}

/** Import into the system as CryptoKey the given base64 encoded PK
 *
 * @param PK    base64 encoded public key
 * @return {Promise}  null
 * @ignore
 */
function importPK(PK){
  return crypto.subtle.importKey(
      "jwk",
      JSON.parse(Buffer.from(PK, "base64")),
      {
        name: "RSA-OAEP",
        hash: {name: hashFunction},
      },
      false,
      ["wrapKey"]
  )
      .then((publicKey) => { userPublicKeys.set(encryptionObject, publicKey); return true })
      .catch((error) => { throw new Error(`Error importing public key:\n${error}`) });
}

/** Export the given public key as a base64 encoded string
 *
 * @param PK      {CryptoKey} The public key
 * @return {Promise.<string>} Return a Promise of the exported public key
 * @ignore
 */
function exportPK(PK) {
  return crypto.subtle.exportKey("jwk", PK)
      .then((keydata) => Buffer.from(JSON.stringify(keydata)).toString("base64"))
      .catch((error) => { throw new Error(`Error exporting public key:\n${error}`) });
}

/** Return an hash of given data
 *
 * @param aBuffer {ArrayBuffer} The buffer from which compute the hash
 * @ignore
 */
function H(aBuffer) {
  return crypto.subtle.digest({name: hashFunction}, aBuffer)
      .then((hash) => new Uint8Array(hash))
      .catch((error) => { throw new Error(`Impossible to hash the given data:\n${error}`) });
}
/**
 * Hash the curret UTC timestamp, according to selected algorithm.
 * By default it is used SHA-256
 *
 * @param      {number} ts           The UTC timestamp as milliseconds from 1st January 1970. Default value is null
 * @return     {Promise<Uint8Array>}  A Promise of an Uint8Array of 12 integers that represent a slice of timestamp hash
 * @ignore
 */
function timestampHash(ts = null) {
  // get timestamp if not provided
  if (!ts) ts = new Date().getTime();

  // convert timestamp to Uint8Array
  const bytes = [];
  for (let i = 0; i < 8; i++, ts= (ts-(ts & 0xff))/256) bytes.unshift(ts & 0xff); // not shifted to preserve all the 53 bit precision
  return H(new Uint8Array(bytes))
      .then((hash) => hash.slice(0,12));
}