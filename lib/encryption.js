"use strict";

const base64 = require("base64-js");

// private data structure
const publicKeys = new WeakMap();
const privateKeys = new WeakMap();
const commonKeys = new Map();

let encryptionObject = null;

// settings
const tagLength = 128;
const RSAkeyLength = 2048;

class EncryptionLayer {
  constructor() {
    // every time a new object is created, old object and its keys are removed
    encryptionObject = this;
  }
  /**
   * This function initialize the encryption layer, getting right user's keys
   * @param password  string    the user password
   */
  initLayer(password, pk, sk) {
    if (pk && sk) {
      publicKeys.set(this, pk);
      privateKeys.set(this, sk);
    }
    else {
      return generateKeyPair(password)
          .then((ck) => {
            publicKeys.set(encryptionObject, ck.publicKey);

          })
    }
  }

  static  wrapKey(key) {
    return crypto.subtle.wrapKey(
        "raw",
        key,
        publicKeys.get(encryptionObject),
        {
          name: "RSA-OAEP",
          hash: {name: "SHA-256"},
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
        privateKeys.get(encryptionObject),
        {
          name: "RSA-OAEP",
          modulusLength: RSAkeyLength,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]), //65537
          hash: {name: "SHA-256"},
        },
        {
          name: "AES-GCM",
          length: 256
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
  static  generateCommonKey(sboxId) {
    return crypto.subtle.generateKey(
        {
          name: "AES-GCM",
          length: 256
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
          length: 256
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

function getWrapSKKey(password, info) {
  let keyHash = null;
  return H(new TextEncoder().encode(password))
      .then((hash) => {
        keyHash = hash; // save the hash for later
        return crypto.subtle.importKey(
            "raw",
            crypto.getRandomValues(new Uint8Array(32)), //your raw key data as an ArrayBuffer
            {
              name: "HKDF",
            },
            false, //whether the key is extractable (i.e. can be used in exportKey)
            ["deriveKey"] //can be any combination of "deriveKey" and "deriveBits"
        )
      })
      .then((ikey) => crypto.subtle.deriveKey(
          {
            name: "HKDF",
            info: new TextEncoder().encode(info),
            salt: keyHash,
            hash: {name: "SHA-256"},
          },
          ikey,
          {
            name: "AES-GCM",
            length: 256,
          },
          false,
          ["wrapKey", "unwrapKey"]
      ))
}


/**
 *
 * @return {Promise.<CryptoKey>} The container of public-private keys
 */
function generateKeyPair(password) {
  return crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: RSAkeyLength,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: {name: "SHA-256"},
      },
      true, //whether the key is extractable (i.e. can be used in exportKey)
      ["wrapKey", "unwrapKey"]
  )
}
/** Return an hash of given data
 *
 * @param aBuffer
 *
 */
function H(aBuffer) {
  return crypto.subtle.digest({name: "SHA-256"}, aBuffer)
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