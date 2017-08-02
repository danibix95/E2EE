"use strict";

const sboxes = new Map() // id : SBox Object

/*
* signUp(username, password, other_data = {}) -> result
 login(username, password) -> token
 createSBox(title) -> sbox_id
 grantAccess(user_id, sbox_id) -> result
 revokeAccess(user_id, sbox_id) -> result
 insert(message, sbox_id) -> result
 retrieve(sbox_id, last_download = null) -> list_of_messages
 insertFile(file, sbox_id) -> result
 retrieveFiles(sbox_id, last_download = null) -> list_of_blob
 removeResource(resource_id, sbox_id) -> result
 removeSecurityBox(sbox_id) -> result // Static for SBOX class
 deleteAccount() -> result
 search(username) -> user_id
 sync() -> list_of_conversation_ids
 */


/* Private/Public key -> saved in the session storage
*
* */
// let JS Object have private attributes
const _ = require('private-parts').createKey();

const API = require("./api_connect");
const E2E = require("./encryption");

// reference to SBoxes schema on Chino
let dataSchema = null;
// reference to PKs schema on Chino
let keysSchema = null;
// reference to information schema on Chino
let linkSchema = null;
// Chino group who can create/read public keys
let keysGroup = null;
// Chino userSchema
let userSchema = null;

class User {
  constructor(auth, userId) {
    // keep track (on client side) of users who can access the SBox
    // double checked on the server
    _(this).auth = auth;
    _(this).userId = userId;
    _(this).sboxes = new Map(); // id : SBox
  }
  get sboxesId() {
    return _(this).sboxes.keys(); // TODO: change to Sync with Chino
  }
  // used for updating the auth object (e.g. refresh token)
  updateAuth(newAuth) {
    _(this).auth = newAuth;
  }
  createSBox(title) {
    // TODO: crea una nuova SBox (su Chino) - crea il documento i 3 schemi e il gruppo relativo, crea chiave CK, carica criptata su Chino con user PK, crea JS object - save the SBox to

    // here add sbox to sboxes attribute
    return "sboxId";
  }
  removeSBox(sboxId) {
    // TODO: remove SBox from Chino, 3 docs + group, delete JS object
    // here remove sbox from sboxes attribute
  }
  sync() {
    // TODO: complex function to retrieve all the modifications that happened to sboxes
  }
  static signUp(username, password, other_data = {}) {
    // TODO: crea un nuovo utente su Chino; dai permessi di lettura/creazione sullo schema delle chiavi (gruppo keys?)
  }
  static login(username, password) {
    // TODO: autentica l'utente, ottieni le sue informazioni e le sue chiavi, inizializza il layer di encryption (e ritorna un User Object
  }
  // return user_id if exist
  static search(username) {
    const filter = {
      result_type: "ONLY_ID",
      filter_type: "and",
      filter: [
        {
          field: "last_name",
          type: "eq",
          value: username   /* username validation is done by Chino */
        }
      ]
    }
    return API.post(`/search/users/${userSchema}`, filter, _(this).auth)
        .then((result) => result.data.count === 1 ? result.data.users[0].user_id : null)
  }
  static deleteAccount() {
    // TODO: delete only user information from Chino, no messaggi e file (se non vengono più utilizzati possono essere messi come disattivati fino allo scadere del tempo di legge.
  }
}

class SBox {
  constructor(info) {
    _(this).id = info.sboxId;
    _(this).groupId = info.groupId; // group that can access to this
    _(this).commonKeys = info.keysId;
    _(this).documentsId = info.documentsId;
    _(this).filesId = info.filesId;
    _(this).users = new Array();
  }

  /** Grant to the selected user the permission to access the content of this SBox
   *
   * @param ownId     {string}    The user id of who is granting the access
   * @param username  {string}    The user id of who will receive the permission to access
   * @param auth      {object}    The authentication object needed to access Chino API
   * @return {Promise.<boolean>}  Return true if the operation was successful
   *                              Return false if selected username doesn't exist
   *                              Thrown an Error if there's any API exception
   */
  grantAccess(ownId, username, auth = null) {
    let userId = null;

    return User.search(username)  // get User id
        .then((usrId) => {
          // if no user with this username (or more than 1) stop the execution
          if (!usrId) return false;

          userId = usrId;

          const filter = {
            result_type: "FULL_CONTENT",
            filter_type: "and",
            filter: [{
              field: "user_id",
              type: "eq",
              value: ownId
            }]
          }

          // get my wrapped common key
          return API.post(`/search/documents/${_(this).commonKeys}`, filter, auth)
              .then((result) => result.data.documents[0].content.enc_ck);
        })
        .then((commonKey) => E2E.unwrapKey(this, commonKey))  // unwrap common key
        .then(() => { // get the selected user public key
          const filter = {
            result_type: "FULL_CONTENT",
            filter_type: "and",
            filter: [{
              field: "user_id",
              type: "eq",
              value: userId
            }]
          }
          return API.post(`/search/documents/${keysSchema}`, filter, auth)
              .then((result) => result.data.documents[0].content.public_key);
        })
        .then((PK) => E2E.wrapKey(this, PK))  // wrap the common key for the user with its public key
        .then((WCK) => {
          const ckDoc = {
            content: {
              user_id: userId,
              enk_ck: WCK
            }
          }
          // add the wrapped key to the common keys schema of SBOX
          return API.post(`/schemas/${_(this).commonKeys}/documents`, ckDoc, auth);
        })
        .then(() => API.post(`/groups/${_(this).groupId}/users/${userId}`)) // add user to SBOX group
        .then(() => {
          const lkDoc = {
            content: {
              user_id: userId,
              sbox_id: _(this).sbox_id
            }
          }
          return API.post(`/schemas/${linkSchema}/documents`, lkDoc, auth);
        })
        .then(() => true) // confirm that everything was successfully executed
        .catch((error) => {
          throw new Error(`Impossible to grant access to ${username} user;\n ${error}`);
        });
  }

  /** Revoke to the selected user the permission to access the content of this SBox
   *
   * @param username  {string}    The user id of who will lose the permission to access
   * @param auth      {object}    The authentication object needed to access Chino API
   * @return {Promise.<boolean>}  Return true if the operation was successful
   *                              Return false if selected username doesn't exist
   *                              Thrown an Error if there's any API exception
   */
  revokeAccess(username, auth = null) {
    let userId = null;

    return User.search(username)  // get User id
        .then((usrId) => {
          // if no user with this username (or more than 1) stop the execution
          if (!usrId) return false;

          userId = usrId;

          const filter = {
            result_type: "FULL_CONTENT",
            filter_type: "and",
            filter: [{
              field: "user_id",
              type: "eq",
              value: userId
            }]
          }

          // get CKeys doc id
          return API.post(`/search/documents/${_(this).commonKeys}`, filter, auth)
              .then((result) => result.data.documents[0].document_id);
        })
        .then((docId) => API.del(`/documents/${docId}?force=true`)) // delete previous doc
        .then(() => {
          const filter = {
            result_type: "FULL_CONTENT",
            filter_type: "and",
            filter: [
              {
                field: "user_id",
                type: "eq",
                value: userId
              },
              {
                field: "sbox_id",
                type: "eq",
                value: _(this).id
              }
            ]
          }
          // get Link doc id
          return API.post(`/search/documents/${linkSchema}`, filter, auth)
              .then((result) => result.data.documents[0].document_id);
        })
        .then((docId) => API.del(`/documents/${docId}?force=true`)) // delete previous doc
        .then((userId) => API.del(`/groups/${_(this).groupId}/users/${userId}`))  // remove user from group
        .then(() => true)
        .catch((error) => {
          throw new Error(`Impossible to grant access to ${username} user;\n ${error}`)
        });
  }
  insert(userId, message, additionalData = null, auth = null) {
    const timestamp = new Date().getTime();
    if (E2E.hasCommonKey(this)) {
      return encryptAndUpload();
    }
    else {
      const filter = {
        result_type: "FULL_CONTENT",
        filter_type: "and",
        filter: [{
          field: "user_id",
          type: "eq",
          value: userId
        }]
      }

      // get my wrapped common key
      return API.post(`/search/documents/${_(this).commonKeys}`, filter, auth)
          .then((result) => result.data.documents[0].content.enc_ck)
          .then((commonKey) => E2E.unwrapKey(this, commonKey))
          .then(() => encryptAndUpload())
    }

    const encryptAndUpload = () =>
        E2E.encrypt(this, message, timestamp, additionalData)
            .then((cipher) => {
              const doc = {
                content: {
                  enc_message: cipher,
                  written_on: timestamp,
                  writer_id: userId
                }
              }
              return API.post(`/schemas/${_(this).documentsId}/documents`, doc, auth)
            })
            .then(() => true)
            .catch((error) => { throw new Error(`Impossible to insert the message:\n${error}`)})
  }
  retrieve(userId, auth = null, last_download = null) {
    // TODO: make call to Chino
  }
  insertFile(userId, file, auth = null) {
    // TODO: make call to Chino
  }
  retrieveFiles(userId, auth = null, last_download = null) {
    // TODO: make call to Chino
  }
  removeResource(resource_id, auth = null, isFile = null) {
    // TODO: make call to Chino
  }
}

/* Other functions */
function throwError(status) {
  throw new Error(`API exception:\n${status}`);
}

/* ===================== */
/* Publish SDK functions */
/* ===================== */
module.exports = function (options) {
  const requiredOptions = ["dataSchema", "keysSchema", "linkSchema", "keysGroup", "userSchema"];
  if (requiredOptions.some((opt) => !options.hasOwnProperty(opt)))
    throw new Error("Impossible to initialize the client (Wrong options given.");
  // set up the client settings
  dataSchema = options.dataSchema;
  keysSchema = options.keysSchema;
  linkSchema = options.linkSchema;
  keysGroup = options.keysGroup;
  userSchema = options.userSchema;

  // return classes
  return {
    User,
    SBox
  }
}

