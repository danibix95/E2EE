"use strict";

// let JS Object have private attributes
const _ = require('private-parts').createKey();

const API = require("./api_connect");
const E2E = require("./encryption");

// reference to SBoxes repo
let sboxRepo = null;
// reference to SBoxes schema on Chino
let sboxSchema = null;
// reference to PKs schema on Chino
let keysSchema = null;
// reference to information schema on Chino
let linkSchema = null;
// Chino group who can create/read public keys
let keysGroup = null;
// Chino userSchema
let userSchema = null;
// let APP id
let appId = null;
// E2E object
let encLayer = null;

/* ==================== */
/*     SBOX Schemas     */
/* ==================== */
/* Needs to be created dynamically when a new SBox document is created */
const keyStorage = (id) => ({
  description: `SBox ${id} Keys`,
  structure: {
    fields: [
      {
        name: "user_id",
        type: "string",
        indexed: true
      },
      {
        name: "enc_ck",
        type: "base64"
      }
    ]
  }
});

const sboxDocuments = (id) => ({
  description: `SBox ${id} Documents`,
  structure: {
    fields: [
      {
        name: "enc_doc",
        type: "base64",
      },
      {
        name: "written_on",
        type: "datetime",
        indexed: true
      },
      {
        name: "writer_id",
        type: "string",
        indexed: true
      },
      {
        name: "ad",
        type: "json"
      }
    ]
  }
});

const sboxFiles = (id) => ({
  description: `SBox ${id} Files`,
  structure: {
    fields: [
      {
        name: "enc_file",
        type: "blob",
      },
      {
        name: "blob_id",
        type: "string",
        indexed: true
      },
      {
        name: "uploaded_on",
        type: "datetime",
        indexed: true
      },
      {
        name: "uploader_id",
        type: "string",
        indexed: true
      },
      {
        name: "file_iv",
        type: "base64"
      },
      {
        name: "file_hash",
        type: "base64"
      },
      {
        name: "ad",
        type: "json"
      }
    ]
  }
});
/* ==================== */

class User {
  /**
   *
   * @param auth
   * @param refreshToken
   * @param userId
   * @param username
   */
  constructor(auth, refreshToken, userId, username) {
    // keep track (on client side) of users who can access the SBox
    // double checked on the server
    _(this).auth = auth;
    _(this).refreshToken = refreshToken;
    _(this).userId = userId;
    _(this).username = username;
    _(this).sboxes = new Map(); // id : SBox
  }

  /**
   *
   * @return {String}
   */
  get userId() {
    return _(this).userId;
  }

  /**
   *
   * @return {String|null}
   */
  get username() {
    return _(this).username;
  }

  /** Return current local the id of Sboxes belonging to the user.
   *  Note: this method doesn't synchronize with the server.
   *
   * @return {Iterator.<String>}
   */
  get sboxesId() {
    return _(this).sboxes.keys();
  }

  /**
   *
   * @param id
   * @return {SBox}
   */
  getSBox(id) {
    return _(this).sboxes.get(id);
  }

  /** used for updating the auth object (e.g. refresh token)
   *
   * @return {Promise.<Number>}
   */
  updateAuth() {
    const data = {
        grant_type: API.GRANT_TYPES.RFS_TOKEN,
        refresh_token: _(this).refreshToken,
        client_id: appId
    };

    return API.post(`/auth/token`, data, _(this).auth, API.CONT_TYPES.FORM_DATA)
        .then((result) => {
          _(this).auth.id = result.data.access_token;
          _(this).refreshToken = result.data.refresh_token;

          // return the expire time in seconds
          return result.data.expires_in;
        })
  }

  /**
   *
   * @param name
   * @return {Promise.<Boolean>}
   */
  createSBox(name) {
    let sboxObject = null;
    let newSboxId = null;
    // create an empty sbox, then get the id, use it for creating substructure,
    // then update sbox with substructure ids and add permissions to sbox group
    const sbox = {
      content : {
        name: name,
        keys: "",
        group: "",
        files: "",
        documents: ""
      }
    };

    const url = `/repositories/${sboxRepo}/schemas`;

    /* create the 3 schemas associated with the SBox */
    return API.post(url, keyStorage(_(this).userId), _(this).auth)
        .then((result) => {
            sbox.content.keys = result.data.schema.schema_id;
            return API.post(url, sboxDocuments(_(this).userId), _(this).auth)
        })
        .then((result) => {
            sbox.content.documents = result.data.schema.schema_id;
            return API.post(url, sboxFiles(_(this).userId), _(this).auth)
        })
        .then((result) => {
            sbox.content.files = result.data.schema.schema_id;
            return API.post(`/groups`,
                {
                  group_name: `SBox group ${new Date().getTime()}`,
                  attributes: { sboxOwner : _(this).userId }
                },
                _(this).auth
            )
        })
        .then((result) => {
            sbox.content.group = result.data.group.group_id;
            return API.post(`/schemas/${sboxSchema}/documents`, sbox, _(this).auth);
        })
        .then((result) => {
            newSboxId = result.data.document.document_id;

            /* Grant permissions on SBox doc */
            return API.post(
                `/perms/grant/documents/${result.data.document.document_id}/groups/${sbox.content.group}`,
                {
                  manage : ["R", "D"],
                  authorize : ["R", "D", "A"]
                },
                _(this).auth
            );
        })
        /* Grant permissions on keys schema */
        .then(() =>
            API.post(
                `/perms/grant/schemas/${sbox.content.keys}/documents/groups/${sbox.content.group}`,
                {
                  manage: ["C", "R", "D", "S"],
                  authorize: ["C", "R", "D", "S", "A"],
                  created_document: {
                    manage: ["R", "D"],
                    authorize: ["R", "D", "A"]
                  }
                },
                _(this).auth
            )
        )
        /* Grant permissions on documents schema */
        .then(() =>
            API.post(
                `/perms/grant/schemas/${sbox.content.documents}/documents/groups/${sbox.content.group}`,
                {
                  manage: ["C", "R", "D", "L", "S"],
                  authorize: ["C", "R", "D", "L", "S", "A"],
                  created_document: {
                    manage: ["R", "D"],
                    authorize: ["R", "D", "A"]
                  }
                },
                _(this).auth
            )
        )
        /* Grant permissions on files schema */
        .then(() =>
            API.post(
                `/perms/grant/schemas/${sbox.content.files}/documents/groups/${sbox.content.group}`,
                {
                  manage: ["C", "R", "U", "D", "S", "L"],
                  authorize: ["C", "R", "U", "D", "S", "L", "A"],
                  created_document: {
                    manage: ["R", "U", "D"],
                    authorize: ["R", 'U', "D", "A"]
                  }
                },
                _(this).auth
            )
        )
        /* add this user to new sbox group */
        .then(() => API.post(`/groups/${sbox.content.group}/users/${_(this).userId}`, {}, _(this).auth))
        /* create JS object, generate common key for it and save it encrypted on Chino */
        .then(() => {
          const info = {
            name        : name,
            sboxId      : newSboxId,
            keysId      : sbox.content.keys,
            groupId     : sbox.content.group,
            filesId     : sbox.content.files,
            documentsId : sbox.content.documents
          };
          sboxObject = new SBox(info, _(this).userId);

          return E2E.generateCommonKey(sboxObject);
        })
        .then(() => E2E.wrapKey(sboxObject))
        .then((eCK) => {
          const keyDoc = {
            content : {
              user_id: _(this).userId,
              enc_ck: eCK
            }
          };
          return API.post(`/schemas/${sbox.content.keys}/documents`, keyDoc, _(this).auth);
        })
        .then(() => {
          // add this new sbox to this user's sboxes
          _(this).sboxes.set(newSboxId, sboxObject);

          // create same link on Chino
          const linkDoc = {
            content : {
              user_id : _(this).userId,
              sbox_id : newSboxId
            }
          };
          return API.post(`/schemas/${linkSchema}/documents`, linkDoc, _(this).auth);
        })
        .then(() => true)
        .catch((error) => {
          throw new Error(`Impossible to create a new sbox:\n${error}`)
        });
  }

  /**
   *
   * @param sboxId
   * @return {Promise.<Boolean>}
   */
  removeSBox(sboxId) {
    let documents = [];

    return API.get(`/documents/${sboxId}`, {}, _(this).auth)
        .then((result) => Promise.all([
            API.del(`/schemas/${result.data.document.content.keys}`, {force: true, all_content: true}, _(this).auth),
            API.del(`/schemas/${result.data.document.content.documents}`, {force: true, all_content: true}, _(this).auth),
            API.del(`/schemas/${result.data.document.content.files}`, {force: true, all_content: true}, _(this).auth),
        ])
            /* remove group later so I am sure I don't remove permissions over those schemas before deleting them */
            .then(() => API.del(`/groups/${result.data.document.content.group}`, {force: true}, _(this).auth))
        )
        .then(() => {
          const filter = {
            result_type: "FULL_CONTENT",
            filter_type: "and",
            filter: [{
              field: "sbox_id",
              type: "eq",
              value: sboxId
            }]
          };

          return listSearchDocs(linkSchema, filter, _(this).auth, documents);
        })
        /* delete link between users and this sbox */
        .then((documents) => Promise.all(
            documents.map((d) =>
                API.del(`/documents/${d.document_id}`, {force: true}, _(this).auth)
            )
        ))
        .then(() => {
          // delete link locally
          _(this).sboxes.set(sboxId, null); // be sure to remove from memory previous reference
          _(this).sboxes.delete(sboxId);

          return true;
        })
        .catch((error) => {
          throw new Error(`Impossible to delete selected SBox:\n${error}`)
        });
  }

  /** Synchronize local SBox with the one saved on the server.
   *  Note: this function doesn't upload SBox content.
   *
   * @return {Promise.<Boolean>}
   */
  syncSBoxes() {
    const filter = {
      result_type: "FULL_CONTENT",
      filter_type: "and",
      filter: [{
        field: "user_id",
        type: "eq",
        value: _(this).userId
      }]
    };
    let documents = [];

    return listSearchDocs(linkSchema, filter, _(this).auth, documents)
        .then(() => {
          if (documents.length === 0) return documents; // this user doesn't have any sbox

          let newSboxes = documents.filter((d) => !_(this).sboxes.has(d.document_id));
          /* locally remove deleted sboxes */
          Array.from(_(this).sboxes.keys()).filter((id) => !documents.includes(id))
                 .forEach((id) => {
                   _(this).sboxes.set(id, null);
                   _(this).sboxes.delete(id);
                 });

          // for only new sboxes, then retrieve their informations
          return Promise.all(
              newSboxes.map((d) => API.get(`/documents/${d.content.sbox_id}`, {}, _(this).auth))
          );
        })
        .then((nwdoc) => Promise.all(
          nwdoc.map((sbox) => {
            const info = {
              sboxId      : sbox.data.document.document_id,
              keysId      : sbox.data.document.content.keys,
              groupId     : sbox.data.document.content.group,
              filesId     : sbox.data.document.content.files,
              documentsId : sbox.data.document.content.documents,
            };
            // create sbox locally
            const newSbox = new SBox(info, _(this).userId);
            _(this).sboxes.set(sbox.document_id, newSbox);

            const filter = {
              result_type: "FULL_CONTENT",
              filter_type: "and",
              filter: [{
                field: "user_id",
                type: "eq",
                value: _(this).userId
              }]
            };

            return searchDoc(info.keysId, filter, _(this).auth)
                .then((doc) => E2E.unwrapKey(newSbox, doc.content.enc_ck));
          })
        ))
        .then(() => true)
        .catch((error) => {
          throw new Error(`Impossible to synchronize sboxes:\n${error}`);
        });
  }

  /** Return the user id of the user
   *  corresponding to the given username, if it exists.
   *
   * @param username  {String}  The user username
   * @return {Promise.<String | null>}
   *                            Return the user id if the given user is found,
   *                            otherwise return null.
   */
  search(username) {
    const filter = {
      result_type: "ONLY_ID",
      filter_type: "and",
      filter: [
        {
          field: "username",
          type: "eq",
          value: username   /* username validation is done by Chino */
        }
      ]
    };
    return API.post(`/search/users/${userSchema}`, filter, _(this).auth)
        .then((result) => result.data.count === 1 ? result.data.users[0].user_id : null);
  }

  /** Log out this user from its account and remove every reference to himself.
   *
   * @return {Promise.<Boolean>}  Return true if the process end successfully,
   *                              otherwise throw an Error
   */
  logout() {
    return API.post(`/auth/revoke_token`, {token: _(this).auth.id, client_id: appId})
        .then(() => {
          // force delete all references in memory about users and SBoxes
          _(this).sboxes.clear();

          return true;
        })
        .catch((error) => {
          throw new Error(`Impossible to log out from this account:\n${error}`);
        })
  }

  /**
   *
   * @return {Promise}
   */
  deleteAccount() {
    /* rimuovi tutti le chiavi dagli schemi delle sbox, rimuovi link, rimuovi la chiave pubblica, rimuovi gruppi, rimuovi account*/
    const filter = {
      result_type: "FULL_CONTENT",
      filter_type: "and",
      filter: [{
        field: "user_id",
        type: "eq",
        value: _(this).userId
      }]
    };

    let documents = [];

    /* get from link schema all the sbox for this user */
    return listSearchDocs(linkSchema, filter, _(this).auth, documents)
        /* for each SBox get its schemas */
        .then(() =>
          Promise.all(
              documents.map((d) => API.get(`/documents/${d.content.sbox_id}`))
          )
        )
        /* then remove own key document from each SBox keys schema */
        .then((results) => Promise.all(
            results.map(
                (r) => API.post(`/search/${r.data.document.content.keys}`, filter, _(this).auth)
                .then((result) => {
                  if (result.data.count === 1) {
                    return result.data.documents[0];
                  }
                  else {
                    throw new Error(`Common Key for ${_(this).userId} not found!`);
                  }
                })
                .then((d) => API.del(`/documents/${d}`, {force:true}, _(this).auth))
            )
        ))
        /* delete all SBox link documents from link schema */
        .then(() =>
            Promise.all(
                documents.map(
                  (d) => API.del(`/documents/${d.document_id}`, {force:true}, _(this).auth)
                )
            )
        )
        /* delete user PK */
        .then(() => searchDoc(keysSchema, filter, _(this).auth))
        .then((doc) => API.del(
            `/document/${doc.document_Id}`,
            { force: true },
            _(this).auth
        ))
        /* get user info for next step */
        .then(() => API.get("/users/me", {}, _(this).auth))
        /* remove this user from groups he belongs to */
        .then((res) => Promise.all(res.data.user.groups.map(
            (g) => API.del(`/groups/${g}/users/${_(this).userId}`, {}, _(this).auth)
        )))
        /* finally delete own account */
        .then(() => API.del(`/users/${this.userId}`, {force: true}, _(this).auth))
        /* remove from local memory important material */
        .then(() => {
          _(this).auth = null;
          _(this).sboxes.clear();

          new E2E(); // definitely delete all the keys
          return true;
        })
        .catch((error) => {
          throw new Error(`Impossible to delete own account:\n${error}`);
        });
  }

  /** With the given informations, it signs up the user
   *  to Chino server, it initialize the Encryption Layer
   *  and it save on Chino created user's keys.
   *
   * @param username      {String} The username that will help to identify the user.
   * @param chinoPassword {String} The password used to authenticate the user on Chino server.
   * @param keyPassword   {String} The password used to encrypt the user private key. It must be
   *                               different from Chino password and mustn't be lose.
   *                               It won't be transmitted to any server.
   * @param other_data    {Object} Other information linked to user [optional]
   * @param info          {Object} Other information that can be used for encrypting data
   * @param auth          {Object} The material used for authenticating on Chino server
   * @return {Promise.<Boolean>}   Return true if the process end successfully,
   *                               otherwise it throws an Error
   */
  static signUp(username, chinoPassword, keyPassword, other_data = {}, info = {}, auth = null) {
    encLayer = new E2E();
    // tmp public key
    let PK = null;

    return encLayer.initEncLayer(keyPassword, info)
        .then((keys) => {
          const userData = {
            username: username,
            password: chinoPassword,
            attributes: {
              private_key: keys.sk,
              user_info : other_data
            },
            is_active: true
          };

          PK = keys.pk;

          return API.post(`/user_schemas/${userSchema}/users`, userData, auth);
        })
        .then((result) => Promise.all([
            API.post(`/groups/${keysGroup}/users/${result.data.user.user_id}`, {}, auth),
            API.post(`/schemas/${keysSchema}/documents`, {
              content: {
                user_id: result.data.user.user_id,
                public_key: PK
              }
            }, auth)
        ]))
        .then(() => true)
        .catch((error) => { throw new Error(`Impossible to sign up:\n${error}`) });
  }

  /** Log the use into the system, starting the Encrytion layer (setting up the keys)
   *
   * @param username      {String} The username that will help to identify the user.
   * @param chinoPassword {String} The password used to authenticate the user on Chino server.
   * @param keyPassword   {String} The password used to encrypt the user private key. It must be
   *                               different from Chino password and mustn't be lose.
   *                               It won't be transmitted to any server.
   * @param info          {Object} Other information that can be used for encrypting data.
   * @return {Promise.<User>} Return a User object that can be used for managing own data.
   */
  static login(username, chinoPassword, keyPassword, info = {}) {
    if (!username || !chinoPassword || !keyPassword)
      throw new Error("Missing credentials");

    encLayer = new E2E();

    const loginData = {
      grant_type: API.GRANT_TYPES.PASSWORD,
      username: username,
      password: chinoPassword,
      client_id: appId
    };

    const userData = {
      auth : null,
      refreshToken: null,
      pk : null,
      sk : null,
      username : null
    };

    return API.post(`/auth/token`, loginData, null, API.CONT_TYPES.FORM_DATA)
        .then((result) => {
          userData.auth = {id: result.data.access_token, secret: {type: "bearer"}};
          userData.refreshToken = result.data.refresh_token;

          return API.get(`/users/me`, {}, userData.auth)
        })
        .then((user) => {
          const filter = {
            result_type: "FULL_CONTENT",
            filter_type: "and",
            filter: [{
              field: "user_id",
              type: "eq",
              value: user.data.user.user_id
            }]
          };

          userData.userId = user.data.user.user_id;
          userData.username = user.data.user.username;
          userData.sk = user.data.user.attributes.private_key;

          return API.post(`/search/${keysSchema}`, filter, userData.auth);
        })
        .then((result) => {
          if (result.data.documents.length !== 1)
            throw new Error("Missing user or it hasn't been indexed yet!");

          userData.pk = result.data.documents[0].content.public_key;
          return encLayer.startEncLayer(keyPassword, userData.pk, userData.sk, info);
        })
        .then(() => {
          return new User(
              userData.auth,
              userData.refreshToken,
              userData.userId,
              userData.username
          );
        })
        .catch((error) => {
          throw new Error(`Impossible to login with this credentials:\n${error}`);
        });
  }
}

class SBox {
  /** The SBox class
   *
   * @param info  {Object}      The object containing
   * @param owner {String|null} The id of the user who create the SBox. It's optional.
   */
  constructor(info, owner = null) {
    this.name = info.name;
    _(this).id = info.sboxId;
    _(this).groupId = info.groupId; // group that can access to this
    _(this).commonKeys = info.keysId;
    _(this).documentsId = info.documentsId;
    _(this).filesId = info.filesId;
    _(this).users = new Set();

    // add the owner id
    if (owner) _(this).users.add(owner);
  }

  get id() {
    return _(this).id;
  }

  /** Locally remove users reference from this SBox */
  clearUsers() {
    _(this).users.clear();
  }

  /**
   * Return the users with the permission to access to this SBox.
   * Note: this method return only local information.
   * Before using this method is recommended to run syncUsers method.
   */
  get users() {
    _(this).users.values();
  }

  /** Synchronize local users of this SBox with the server users
   *
   * @return {Promise.<Boolean>}  Returns true if operation end successfully,
   *                              otherwise it throws a Error.
   */
  syncUsers(caller) {
    const filter = {
      result_type: "FULL_CONTENT",
      filter_type: "and",
      filter: [
        {
          field: "sbox_id",
          type: "eq",
          value: _(this).id
        }
      ]
    };

    let docs = [];

    return listSearchDocs(linkSchema, filter, _(caller).auth, docs)
        .then(() => {
          if (docs.length === 0) throw new Error("No document found");
          // remove useless id
          Array.from(_(this).users.values()).filter((id) => !docs.includes(id))
               .forEach((id) => {
                 _(this).users.delete(id);
               });

          // add new ids
          docs.forEach((d) => { _(this).users.add(d) });
          // confirm successful operation
          return true;
        })
        .catch((error) => {
          throw new Error(`Impossible to synchronize users of this SBox:\n${error}`);
        });
  }

  /** Grant to the selected user the permission to access the content of this SBox
   *
   * @param caller     {User}     The user object of who is granting the access
   * @param username  {string}    The user id of who will receive the permission to access
   * @return {Promise.<Boolean>}  Return true if the operation was successful
   *                              Return false if selected username doesn't exist
   *                              Thrown an Error if there's any API exception
   */
  grantAccess(caller, username) {
    let userId = null;

    return caller.search(username)  // get User id
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
              value: caller.userId
            }]
          };

          // get my wrapped common key
          return searchDoc(_(this).commonKeys, filter, _(caller).auth)
              .then((doc) => doc.content.enc_ck);
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
          };
          return searchDoc(keysSchema, filter, _(caller).auth)
              .then((doc) => doc.content.public_key);
        })
        .then((PK) => {
          return E2E.wrapKey(this, PK)})  // wrap the common key for the user with its public key
        .then((WCK) => {
          const ckDoc = {
            content: {
              user_id: userId,
              enc_ck: WCK
            }
          };
          // add the wrapped key to the common keys schema of SBOX
          return API.post(`/schemas/${_(this).commonKeys}/documents`, ckDoc, _(caller).auth);
        })
        .then(() => API.post(`/groups/${_(this).groupId}/users/${userId}`, {}, _(caller).auth)) // add user to SBOX group
        .then(() => {
          // save user locally and then online
          _(this).users.add(userId);

          const lkDoc = {
            content: {
              user_id: userId,
              sbox_id: _(this).id
            }
          };

          return API.post(`/schemas/${linkSchema}/documents`, lkDoc, _(caller).auth);
        })
        .then(() => true) // confirm that everything was successfully executed
        .catch((error) => {
          throw new Error(`Impossible to grant access to ${username} user;\n ${error}`);
        });
  }

  /** Revoke to the selected user the permission to access the content of this SBox
   *
   * @param username  {string}    The user id of who will lose the permission to access
   * @return {Promise.<Boolean>}  Return true if the operation was successful.
   *                              Return false if selected username doesn't exist.
   *                              Thrown an Error if there's any API exception
   * @param caller
   */
  revokeAccess(caller, username) {
    let userId = null;

    return caller.search(username)  // get User id
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
          };

          // get CKeys doc id
          return searchDoc(_(this).commonKeys, filter, _(caller).auth)
              .then((doc) => doc.document_id);
        })
        .then((docId) => API.del(`/documents/${docId}`, { force : true}, _(caller).auth)) // delete previous doc
        .then(() => {
          // delete user locally
          _(this).users.delete(userId);

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
          };
          // get Link doc id
          return searchDoc(linkSchema, filter, _(caller).auth)
              .then((doc) => doc.document_id);
        })
        .then((docId) => API.del(`/documents/${docId}`, { force : true}, _(caller).auth)) // delete previous doc
        .then(() => API.del(`/groups/${_(this).groupId}/users/${userId}`, {}, _(caller).auth))  // remove user from group
        .then(() => true)
        .catch((error) => {
          throw new Error(`Impossible to grant access to ${username} user;\n ${error}`)
        });
  }

  /** Encrypt the given document for this SBox and insert inside it
   *
   * @param caller          {User}          The user object of who own the key
   * @param document        {Object|string} The document that needs to be encrypted
   * @param additionalData  {Object}        Optional additional data used for encrypting algorithm
   * @return {Promise.<Boolean>}            Return true if the encryption and upload operations
   *                                        are completed successfully
   */
  insert(caller, document, additionalData = {}) {
    const encryptAndUpload = () => {
        const timestamp = stripTimestamp(new Date());
        return E2E.encrypt(this, document, new Date(timestamp).getTime(), additionalData)
            .then((cipher) => {
              const doc = {
                content: {
                  enc_doc: cipher,
                  written_on: timestamp,
                  writer_id: caller.userId,
                  ad: additionalData
                }
              };
              return API.post(`/schemas/${_(this).documentsId}/documents`, doc, _(caller).auth)
            })
            .then(() => true)
            .catch((error) => { throw new Error(`Impossible to insert the message:\n${error}`)})
    };

    if (E2E.hasCommonKey(this)) {
      return encryptAndUpload();
    }
    else {
      return retrieveCK(this, caller.userId, _(caller).auth)
          .then(() => encryptAndUpload())
          .catch((error) => {
            throw new Error(`Impossible to find the key to unlock the SBox content before INSERT operation:\n${error}`);
          });
    }
  }

  /**
   *
   * @param caller
   * @param lastDownload
   * @param toSort
   * @return {*}
   */
  retrieve(caller, lastDownload = null, toSort = true) {
    let documents = [];

    const selectRetriever = () => {
      if (lastDownload) {
        const filter = {
          result_type: "FULL_CONTENT",
          filter_type: "and",
          filter: [{
            field: "written_on",
            type: "gte",
            value: stripTimestamp(lastDownload)
          }]
        };
        return listSearchDocs(_(this).documentsId, filter, _(caller).auth, documents)
      }
      else {
        const params = {
          limit : 50,
          offset: 0,
          full_document : true
        };
        return listDocs(_(this).documentsId, params, _(caller).auth, documents)
      }
    };

    const download = () =>
        selectRetriever().then(() =>
            Promise.all(documents.map((d) =>{
                return E2E.decrypt(
                    this,
                    d.content.enc_doc,
                    new Date(d.content.written_on).getTime(),
                    d.content.ad
                )
                    .then((plaintext) => ({
                      id: d.document_id,
                      data : plaintext,
                      timestamp : d.content.written_on
                    }))
            }
            ))
        )
        .then((docs) =>
            toSort
                ? docs.sort(compareTimestamp)
                : docs
        )
        .catch((error) => {
          throw new Error(`Something went wrong retrieving documents:\n${error}`);
        });

    if (E2E.hasCommonKey(this)) {
      return download();
    }
    else {
      return retrieveCK(this, caller.userId, _(caller).auth)
          .then(() => download())
    }
  }

  /**
   *
   * @param caller
   * @param file
   * @param additionalData
   * @return {Promise.<Boolean>} Return true if success
   */
  insertFile(caller, file, additionalData = {}) {
    const chunkSize = 2 * 1024;

    const chunkAndUpload = () => {
      const upDoc = {
        content: {
          blob_id: "",
          uploaded_on: stripTimestamp(new Date()),
          uploader_id: caller.userId,
          file_iv: "",
          file_hash: "",
          ad: additionalData
        }
      };

      const blobDoc = {
        document_id: "",
        field: "enc_file",
        file_name: file.name
      };

      let slices = [];
      let uploadId = null;
      let fileIV = null;
      let fileHash = null;
      let encHash = null;

      return API.post(`/schemas/${_(this).filesId}/documents`, upDoc, _(caller).auth)
          .then((result) => {
              blobDoc.document_id = result.data.document.document_id;

              return API.post(`/blobs`, blobDoc, _(caller).auth)
          })
          .then((result) => {
            uploadId = result.data.blob.upload_id;
            return getBlob(file);
          })
          .then((fileRead) => {
            // plaintext hash
            return crypto.subtle.digest({name: "SHA-256"}, fileRead)
                .then((hash) => {
                  fileHash = Buffer.from(new Uint8Array(hash)).toString("base64");
                })
                .then(() => E2E.encryptFile(this, fileRead, additionalData))
          })
          .then((eData) => {
            fileIV = eData.iv;

            return crypto.subtle.digest({name: "SHA-1"}, eData.cipher)
                .then((hash) => {
                  // save sha-1 hash as HEX
                  encHash = Array.from(new Uint8Array(hash))
                                 .map(b => ('00' + b.toString(16)).slice(-2)).join('');
                })
                .then(() => eData)
          })
          .then((eData) => {
            // cut the encrypted file into chunks and then upload to Chino
            for (let i = 0; i < eData.cipher.byteLength; i+=chunkSize) {
              const blob = eData.cipher.slice(i, i+chunkSize);
              slices.push(
                  {
                    bytes : blob,
                    offset : i,
                    size : blob.byteLength
                  }
              );
            }

            return Promise.all(slices.map((sl) =>
                API.chunk(
                    `/blobs/${uploadId}`,
                    sl.bytes,
                    {
                      blob_offset: sl.offset,
                      blob_length: sl.size
                    },
                    _(caller).auth
                )
            ))
          })
          .then((result) => API.post(`/blobs/commit`, {upload_id : uploadId}, _(caller).auth))
          .then((result) => {
            if (encHash !== result.data.blob.sha1)
              throw new Error("Error during blob upload - hash mismatch!");

            // update uploaded doc
            upDoc.content.blob_id = result.data.blob.blob_id;
            upDoc.content.uploaded_on = stripTimestamp(new Date());
            upDoc.content.uploader_id = caller.userId;
            upDoc.content.file_iv = fileIV;
            upDoc.content.file_hash = fileHash;
            upDoc.content.ad = additionalData;

            return API.put(`/documents/${blobDoc.document_id}`, upDoc, {}, _(caller).auth)
          })
          .then(() => true)
          .catch((err) => { throw new Error(`Impossible to upload the file:\n${err}`) });
    };

    if (E2E.hasCommonKey(this)) {
      return chunkAndUpload();
    }
    else {
      return retrieveCK(this, caller.userId, _(caller).auth)
          .then(() => chunkAndUpload());
    }
  }

  /**
   *
   * @param caller
   * @param auth
   * @param lastDownload
   * @param toSort
   * @return {Promise.<Array>}
   */
  retrieveFiles(caller, lastDownload = null, toSort = true) {
    let documents = [];

    const selectRetriever = () => {
      if (lastDownload) {
        const filter = {
          result_type: "FULL_CONTENT",
          filter_type: "and",
          filter: [{
            field: "uploaded_on",
            type: "gte",
            value: stripTimestamp(lastDownload)
          }]
        };
        return listSearchDocs(_(this).filesId, filter, _(caller).auth, documents)
      }
      else {
        const params = {
          limit : 50,
          offset: 0,
          full_document : true
        };
        return listDocs(_(this).filesId, params, _(caller).auth, documents)
      }
    };

    const downloadFiles = () =>
        selectRetriever()
            .then(() =>
                toSort
                    ? documents.sort(compareTimestamp)
                    : documents
            )
            .then((docs) =>
              Promise.all(docs.map((d) => {
                console.log(d);
                return API.getBlob(`/blobs/${d.content.blob_id}`, {}, _(caller).auth)
                      .then((cipher) => {
                        console.log(cipher);
                        return ({
                          cipher : new Uint8Array(cipher),
                          iv : d.content.file_iv,
                          hash : d.content.file_hash,
                          ad : d.content.ad,
                          id : d.document_id
                        })
                      })
              }
              ))
            )
            .then((files) => Promise.all(
              files.map((ef) =>
                  E2E.decryptFile(this, ef.cipher, ef.iv, ef.ad)
                  .then((blob) =>
                    crypto.subtle.digest({name: "SHA-256"}, blob) // TODO: da sistemare hash sono in base64 now??
                    .then((hash) => {
                      if (compareArray(new Uint8Array(Buffer.from(ef.hash, "base64")), new Uint8Array(hash))) {
                        return {
                          fileId : ef.id,
                          blob: blob
                        };
                      }
                      else {
                        throw new Error("Error downloading blob data: hash mismatch")
                      }
                    })
                  )
              )
            ))
            .catch((rejected) => {
              throw new Error(`Impossible to download a file:\n${rejected}`);
              // console.error(`Impossible to download a file:\n${rejected}`);
              // return rejected; // ignore failed download
            });

    if (E2E.hasCommonKey(this)) {
      return downloadFiles();
    }
    else {
      return retrieveCK(this, caller.userId, _(caller).auth).then(() => downloadFiles());
    }
  }

  /**
   *
   * @param docId
   * @param caller
   * @return {Promise.<Boolean>}
   */
  remove(docId, caller) {
    return API.del(`/documents/${docId}`, {force:true}, _(caller).auth)
        .then(() => true)
        .catch((error) => {throw new Error(`Impossible to delete selected file:\n${error}`)})
  }

  /**
   *
   * @param fileId
   * @param caller
   * @return {Promise.<Boolean>}
   */
  removeFile(fileId, caller) {
    return API.get(`/documents/${fileId}`,{}, _(caller).auth)
        .then((result) => API.del(`/blob/${result.data.content.blob_id}`, {}, _(caller).auth))
        .then(() => API.del(`/documents/${fileId}`, {force:true}, _(caller).auth))
        .then(() => true)
        .catch((error) => {throw new Error(`Impossible to delete selected file:\n${error}`)})
  }
}


/* =============== */
/* Other functions */
/* =============== */
/**
 *
 *
 * @param schemaId
 * @param filter
 * @param auth
 * @return {Promise}
 * @ignore
 */
function searchDoc(schemaId, filter, auth) {
  return API.post(`/search/${schemaId}`, filter, auth)
      .then((res) => res.data.documents[0]);
}

/** Remove milliseconds from the timestamp,
 *  since JS ISO timestamp are not accepted by Chino server
 *
 * @param ts  The timestamp to strip
 * @return {string} Return a string representing the timestamp without milliseconds
 * @ignore
 */
function stripTimestamp(ts) {
  return ts.toISOString().split(".")[0];
}

/**
 *
 * @param a
 * @param b
 * @return {number}
 * @ignore
 */
function compareTimestamp(a, b) {
  const tsA = new Date(a.timestamp).getTime();
  const tsB = new Date(b.timestamp).getTime();

  if (tsA < tsB) return -1;
  if (tsA > tsB) return 1;
  return 0; // equals
}

/** Recursively retrieve all the documents of the selected schema that match the given filter
 *
 * @param schemaId  {string}    The id of the schema that contains the documents to be retrieved
 * @param filter    {object}
 * @param auth      {Object}    The authentication object needed to access Chino API
 * @param documents {Array}     The Array that will contain retrieved documents
 * @param limit     {int}
 * @param offset    {int}
 * @return {Promise.<Boolean>}
 * @ignore
 */
function listSearchDocs(schemaId, filter, auth, documents, offset = 0, limit = 50) {
  let parameters = {
    offset : offset < 0 ? 0 : offset,
    limit : limit < 1 ? 1 : limit
  }

  const search = (params) =>
    API.post(`/search/${schemaId}?offset=${params.offset}&limit=${params.limit}`, filter, auth)
      .then((result) => {
        const results = result.data;

        if (results.count > 0)
          results.documents.forEach((d) => { documents.push(d) });
        if (results.offset + results.limit >= results.total_count)
          return true;  // stop recursion

        params.offset = results.offset + results.limit;
        // recursive call
        return search(params);
      })
      .catch((error) => {
        throw new Error(`Impossible to read documents:\n${error}`);
      });

  return search(parameters);
}

/** Recursively retrieve all the document of the selected schema
 *
 * @param schemaId  {string}    The id of the schema that contains the documents to be retrieved
 * @param params    {Object}    The params needed to iterate over all the documents
 * @param auth      {Object}    The authentication object needed to access Chino API
 * @param documents {Array}     The Array that will contain retrieved documents
 * @return {Promise.<Boolean>}
 * @ignore
 */
function listDocs(schemaId, params, auth, documents) {
  const list = (params) =>
      API.get(`/schemas/${schemaId}/documents`, params, auth)
          .then((result) => {
            const results = result.data;

            if (results.count > 0)
              results.documents.forEach((d) => { documents.push(d) });
            if (results.offset + results.limit >= results.total_count)
              return true;  // stop recursion

            params.offset = results.offset + results.limit;
            // recursive call
            return list(params);
          })
          .catch((error) => {
            throw new Error(`Impossible to read documents:\n${error}`);
          });

  return list(params);
}
/**
 *
 * @param sbox
 * @param userId
 * @param auth
 * @return {Promise.<null>}
 * @ignore
 */
function retrieveCK(sbox, userId, auth = null) {
  const filter = {
    result_type: "FULL_CONTENT",
    filter_type: "and",
    filter: [{
      field: "user_id",
      type: "eq",
      value: userId
    }]
  };

  // get my wrapped common key
  return API.post(`/search/${_(sbox).commonKeys}`, filter, auth)
      .then((result) => {
        if (result.data.count === 1) {
          return result.data.documents[0].content.enc_ck;
        }
        else {
          throw new Error(`Common Key for ${userId} not found!`);
        }
      })
      .then((commonKey) => E2E.unwrapKey(sbox, commonKey))
      .catch((err) => {throw new Error(`Key not found:\n${err}`)});
}

/**
 *
 * @param file
 * @return {Promise}
 * @ignore
 */
function getBlob(file) {
  function readBlob(resolve, reject) {
    const reader = new FileReader();

    reader.addEventListener("loadend", (ev) => {
      if (ev.target.readyState == FileReader.DONE) {
        resolve(new Uint8Array(ev.target.result));
      }
      else {
        reject(ev);
      }
    });

    reader.readAsArrayBuffer(file);
  }

  return new Promise(readBlob);
}

/**
 *
 * @param a
 * @param b
 * @return {boolean}
 * @ignore
 */
function compareArray(a, b) {
  if (a.byteLength !== b.byteLength) return false;

  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }

  return true;
}

/* ===================== */
/* Publish SDK functions */
/* ===================== */
module.exports = function (options) {
  const requiredOptions = ["sboxSchema", "keysSchema", "linkSchema", "keysGroup", "userSchema"];
  if (requiredOptions.some((opt) => !options.hasOwnProperty(opt)))
    throw new Error("Impossible to initialize the client (Wrong options given.");
  // set up the client settings
  sboxRepo    = options.sboxRepo;
  sboxSchema  = options.sboxSchema;
  keysSchema  = options.keysSchema;
  linkSchema  = options.linkSchema;
  keysGroup   = options.keysGroup;
  userSchema  = options.userSchema;
  appId       = options.appId;

  // return classes
  return {
    User,
    SBox
  };
}
