"use strict";

class EncryptionLayer {
  /**
   * This function initialize the encryption layer, getting right user's keys
   * @param password  string    the user password
   */
  constructor(password) {

  }

  /**
   *
   * @return {CryptoKey} The container of public-private keys
   */
  static generateKeyPair() {
    return window.crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048, //can be 1024, 2048, or 4096
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
        },
        true, //whether the key is extractable (i.e. can be used in exportKey)
        ["wrapKey", "unwrapKey"] //must be ["encrypt", "decrypt"] or
    );
  }

  static wrapKey(key, publicKey) {
    return window.crypto.subtle.wrapKey(
        "raw",
        key,
        publicKey,
        {
          name: "RSA-OAEP",
          hash: {name: "SHA-256"},
        }
    );
  }

  static unwrapKey(wrappedKey, privateKey) {
    return window.crypto.subtle.unwrapKey(
        "raw",
        wrappedKey,
        privateKey,
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]), //65537
          hash: {name: "SHA-256"},
        },
        {
          name: "AES-GCM",
          length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
  }

  /**
   * This method generate a secret key for AES GCM algorithm
   * @return {CryptoKey} It return an object containing generated key and its parameters
   */
  static generateCommonKey() {
    return window.crypto.subtle.generateKey(
        {
          name: "AES-GCM",
          length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
  }

  static loadCommonKey(ckey) {
    return window.crypto.subtle.importKey(
        "raw",
        ckey,
        {
          name: "AES-GCM",
          length: 256
        },
        false,
        ["encrypt", "decrypt"]
    )
  }

  static exportCommonKey(ckey) {
    return window.crypto.subtle.exportKey("raw", ckey);
  }

  static encrypt(ckey, data) {
    return window.crypto.subtle.encrypt(
        {
          name: "AES-GCM",

          //Don't re-use initialization vectors!
          //Always generate a new iv every time your encrypt!
          //Recommended to use 12 bytes length
          iv: window.crypto.getRandomValues(new Uint8Array(12)),

          //Additional authentication data (optional)
          additionalData: ArrayBuffer,
          tagLength: 128,
        },
        ckey,
        data //ArrayBuffer of data you want to encrypt
    )
        .then(function(encrypted){
          //returns an ArrayBuffer containing the encrypted data
          console.log(new Uint8Array(encrypted));
        })
        .catch(function(err){
          console.error(err);
        });
  }

  static decrypt(ckey, cipher) {
    return window.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: ArrayBuffer(12), //The initialization vector you used to encrypt
          additionalData: ArrayBuffer, //The addtionalData you used to encrypt (if any)
          tagLength: 128, //The tagLength you used to encrypt (if any)
        },
        key, //from generateKey or importKey above
        data //ArrayBuffer of the data
    )
  }
}

module.exports = EncryptionLayer;

/* ======================== */
/* Module Private Functions */
/* ======================== */

/**
 * Hash the curret UTC timestamp, according to selected algorithm.
 * By default it is used SHA-256
 *
 * @param      {string}     sha       The function used to digest the timestamp. Default SHA-256
 * @return     {Promise<Uint8Array>}  A Promise of an Uint8Array of 12 integers that represent a slice of timestamp hash
 */
function timestampHash(sha = "SHA-256") {
  if(! new RegExp("SHA\-(256|384|512)").test(sha)) throw new Error("Selected unknown algorithm");
  // hash function
  const H = (aBuffer) => window.crypto.subtle.digest({name: sha}, aBuffer);

  // get the timestamp
  let ts = new Date().getTime();

  // convert timestamp to Uint8Array
  const bytes = new Array();
  for (let i = 0; i < 8; i++, ts= (ts-(ts & 0xff))/256) bytes.unshift(ts & 0xff); // not shifted to preserve all the 53 bit precision
  return H(new Uint8Array(bytes))
      .then((hash) => new Uint8Array(hash).slice(0,12));
}