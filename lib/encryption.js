"use strict";

const base64 = require("base64-js");

// keys container
const userPublicKeys = new WeakMap(); // only contain one at time (max 1 instance of EncryptionLayer)
const userPrivateKeys = new WeakMap();
const commonKeys = new Map(); // sboxId : cached_key

// private object
let encryptionObject = null;
let protectKey = null;

// settings
const tagLength = 128;
const AESKeyLength = 256;
const RSAkeyLength = 2048;
const hashFunction = "SHA-256";
const pubExp = new Uint8Array([0x01, 0x00, 0x01]); //65537

class EncryptionLayer {
  constructor() {
    // every time a new object is created, old object and its keys are removed
    userPublicKeys.delete(encryptionObject);
    userPrivateKeys.delete(encryptionObject);
    encryptionObject = this;
  }
  /**
   * This function initialize the encryption layer, getting right user's keys
   * @param password  string    the user password
   */
  initEncLayer(password, pk = null, sk = null, info = {}, storeLocally = false) {
    return protectSK(password, info, storeLocally)
        .then((protectKey) => {
          if (pk && sk) {
            return Promise.all([
                importPK(pk),
                importSK(sk)
            ])
                .then(() => null)
          }
          else {
            return generateKeyPair()
                .then((ck) => {
                  // save keys in memory
                  userPublicKeys.set(encryptionObject, ck.publicKey);
                  userPrivateKeys.set(encryptionObject, ck.privateKey);

                  return Promise.all([
                    exportPK(ck.publicKey),
                    exportSK(ck.privateKey, protectKey)
                  ])
                })
          }
        })
        .catch(()=> {});
  }

  static  wrapKey(key) {
    return crypto.subtle.wrapKey(
        "raw",
        key,
        userPublicKeys.get(encryptionObject),
        {
          name: "RSA-OAEP",
          hash: {name: hashFunction},
        }
    )
        .then((key) => base64.fromByteArray(new Uint8Array(key)))
        .catch((err) => {
          throw new Error(`Impossible to export key:\n${err}`)
        })
  }

  static unwrapKey(wrappedKey) {
    return crypto.subtle.unwrapKey(
        "raw",
        new Uint8Array(base64.toByteArray(wrappedKey)),
        userPrivateKeys.get(encryptionObject),
        {
          name: "RSA-OAEP",
          modulusLength: RSAkeyLength,
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
  }

  /** Generate a new CryptoKey for AES GCM algorithm
   *
   * @return {Promise.<CryptoKey>}
   *                  A Promise that returns the corresponding CryptoKey object
   */
  static generateCommonKey(sboxId) {
    return crypto.subtle.generateKey(
        {
          name: "AES-GCM",
          length: AESKeyLength
        },
        true,
        ["encrypt", "decrypt"]
    )
        // save in memory generated key
        .then((key) => { commonKeys.set(sboxId, key); return key })
        .catch((err) => { throw new Error(`Error generating new symmetric key:\n${err}`) })
  }


  /** Takes an exported key and loads it into memory
   *
   * @param ckey      The exported common key
   * @param sboxId    The sbox's id linked to common key
   * @return {Promise.<CrytoKey>}
   *                  A Promise that returns the corresponding CryptoKey object
   */
  static loadCommonKey(ckey, sboxId) {
    return crypto.subtle.importKey(
        "raw",
        new Uint8Array(ckey),
        {
          name: "AES-GCM",
          length: AESKeyLength
        },
        false,
        ["encrypt", "decrypt"]
    )
        // save in memory loaded key
        .then((key) => { commonKeys.set(sboxId, key); return key })
        .catch((err) => { throw new Error(`Impossible to load common key:\n${err}`) })
  }

  static exportCommonKey(ckey) {
    return crypto.subtle.exportKey("raw", ckey)
        .then((key) => new Uint8Array(key))
        .catch((err) => { throw new Error(`Impossible to export common key:\n${err}`) })
  }

  /** Encrypt data with provided symmetric key
   *  and return a cipher text encoded in base64
   *
   * @param ckey      {CryptoKey} The symmetric key (common key)
   * @param data      {Object}    Data to be encrypted
   * @param timestamp {number}    Data creation UTC timestamp as milliseconds from January 1, 1970
   * @param AD        {Object|string|number}    Optional additional data used for encrypting algorithm
   * @return {Promise.<String>}
   *            Return a base64 encoded string that represent the cipher text
   */
  static encrypt(ckey, data, timestamp, AD = "") {
    return timestampHash(timestamp)
        .then((ts) =>
            crypto.subtle.encrypt(
              {
                name: "AES-GCM",
                iv: ts,
                additionalData: new TextEncoder().encode(AD),
                tagLength: tagLength,
              },
              ckey,
              Buffer.from(JSON.stringify(data))  // encode data to get a node buffer that can be decoded later
            )
        )
        .then((encrypted) => base64.fromByteArray(new Uint8Array(encrypted)))
        .catch((err) => {
          throw new Error(`Error encrypting message with symmetric key:\n${err}`);
        })
  }

  /** Decrypt data with provided symmetric key
   *  and return a JS object as plaintext
   *
   * @param ckey      {CryptoKey} The symmetric key (common key)
   * @param cipher    {Object}    Base64 string that represent the cipher text to be decrypted
   * @param timestamp {number}    Data creation UTC timestamp as milliseconds from January 1, 1970
   * @param AD        {Object|string|number}    Optional additional data used for encrypting algorithm
   * @return {Promise.<String>}
   *            Return a JS object as plaintext
   */
  static decrypt (ckey, cipher, timestamp, AD = "") {
    return timestampHash(timestamp)
        .then((ts) =>
            crypto.subtle.decrypt(
                {
                  name: "AES-GCM",
                  iv: ts,
                  additionalData: new TextEncoder().encode(AD),
                  tagLength: tagLength
                },
                ckey,
                base64.toByteArray(cipher)
            )
        )
        .then((plaintext) => JSON.parse(Buffer.from(plaintext)))  // convert to node buffer before to get the object
        .catch((error) => { throw new Error(`Impossible to decrypt ciphertext:\n${error}`) })
  }
}

module.exports = EncryptionLayer;

/* ======================== */
/* Module Private Functions */
/* ======================== */

function protectSK(password, info, storeLocally = false) {
  let keydata = new TextEncoder().encode(password);
  let keyHash = null;

  // check if it's already been generated and stored locally
  if (storeLocally && window.sessionStorage) {
    protectKey = sessionStorage.getItem("protectSK")
  }

  if (protectKey) {
    // directly return the key if it was already generated
    return protectKey;
  }

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

/**
 *
 * @return {Promise.<CryptoKey>} The container of public-private keys
 */
function generateKeyPair() {
  return crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: RSAkeyLength,
        publicExponent: pubExp,
        hash: {name: hashFunction},
      },
      true, //whether the key is extractable (i.e. can be used in exportKey)
      ["wrapKey", "unwrapKey"]
  )
}

function importSK(SK, protectKey){
  let keydata = JSON.parse(Buffer.from(SK, "base64"))

  return crypto.subtle.unwrapKey(
      "jwk",
      keydata.privateKey,
      protectKey,
      {   //these are the wrapping key's algorithm options
        name: "AES-GCM",
        iv: keydata.randomValues,
        additionalData: keydata.randomValues.slice(0,8).reverse(),
        tagLength: tagLength
      },
      { // what kind of key will be used
        name: "RSA-OAEP",
        modulusLength: RSAkeyLength,
        publicExponent: pubExp,
        hash: {name: hashFunction},
      },
      false,
      ["unwrapKey"]
  )
  .then((SK) =>
      crypto.subtle.importKey(
          "jwk",
          SK,
          {
            name: "RSA-OAEP",
            hash: {name: hashFunction},
          },
          false,
          ["unwrapKey"]
      )
  )
  .then((privateKey) => { userPrivateKeys.set(encryptionObject, privateKey) })
  .catch((error) => { throw new Error(`Error importing private key:\n${error}`) });
}
function exportSK(SK, protectKey) {
  let randomValues = crypto.getRandomValues(new Uint8Array(12));
  return window.crypto.subtle.exportKey("jwk", SK)
      .then((keydata) => crypto.subtle.wrapKey(
          "jwk",
          keydata,
          protectKey,
          {
            name: "AES-GCM",
            iv: randomValues,
            additionalData: randomValues.slice(0,8).reverse(),  // use a slice of previous random values
            tagLength: tagLength
          }
      ))
      .then((privateKey) => Buffer.from(
          JSON.stringify({
            privateKey : privateKey,
            randomValues : randomValues
          })
      ).toString("base64"))
      .catch((error) => { throw new Error(`Error exporting public key:\n${error}`) });
}

/** Import into the system as CryptoKey the given base64 encoded PK
 *
 * @param PK    base64 encoded public key
 * @return {Promise}  null
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
      .then((publicKey) => { userPublicKeys.set(encryptionObject, publicKey) })
      .catch((error) => { throw new Error(`Error importing public key:\n${error}`) });
}
function exportPK(PK) {
  return window.crypto.subtle.exportKey("jwk", PK)
      .then((keydata) => Buffer.from(JSON.stringify(keydata)).toString("base64"))
      .catch((error) => { throw new Error(`Error exporting public key:\n${error}`) });
}

/** Return an hash of given data
 *
 * @param aBuffer
 *
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
 */
function timestampHash(ts = null) {
  // get timestamp if not provided
  if (!ts) ts = new Date().getTime();

  // convert timestamp to Uint8Array
  const bytes = new Array();
  for (let i = 0; i < 8; i++, ts= (ts-(ts & 0xff))/256) bytes.unshift(ts & 0xff); // not shifted to preserve all the 53 bit precision
  return H(new Uint8Array(bytes))
      .then((hash) => hash.slice(0,12));
}