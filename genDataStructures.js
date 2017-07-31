"use script"

/*
   This script is meant for creating
   required data structures on Chino server
*/

const API = require("./lib/api_connect");

const auth = {
  id: process.env.CHINO_ID,
  secret: process.env.CHINO_KEY
}

const appData = {
  name: "Safe Deposit Application",
  grant_type: "password",
  client_type : "public"
}

const userSchema = {
  description: "SBoxes Users",
  structure: {
    fields: [
      {
        type: "base64",
        name: "private_key"
      },
      {
        type: "json",
        name: "user_info"
      }
    ]
  }
}

const repoSBox = {
  description: "SBoxes Repository"
}
let dataId = "";

const repoOther = {
  description: "Utility Data Repository"
}
let otherId = "";

const pubKeys = {
  description: "Public Keys",
  structure: {
    fields: [
      {
        name: "user_id",
        type: "string",
        indexed: true
      },
      {
        name: "public_key",
        type: "base64"
      }
    ]
  }
}

const usbox = {
  "description": "User SBoxes",
  "structure": {
    "fields": [
      {
        "name": "user_id",
        "type": "string",
        "indexed": true
      },
      {
        "name": "sbox_id",
        "type": "string",
        "indexed": true
      }
    ]
  }
}

const sbox = {
  description: "SBox",
  structure: {
    fields: [
      {
        name: "keys",
        type: "string",
        indexed: true
      },
      {
        name: "messages",
        type: "string",
        indexed: true
      },
      {
        name: "files",
        type: "string",
        indexed: true
      },
      {
        name: "group_id",
        type: "string",
        indexed: true
      }
    ]
  }
}

const ks = {
  description: "SBox Keys",
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
}

const sbm = {
  description: "SBox Messages",
  structure: {
    fields: [
      {
        name: "enc_message",
        type: "base64",
      },
      {
        name: "written_on",
        type: "date"
      },
      {
        name: "sender_id",
        type: "string"
      }
    ]
  }
}

const sbf = {
  description: "SBox Files",
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
        type: "date"
      },
      {
        name: "sender_id",
        type: "string"
      }
    ]
  }
}

// CALLS
API.post("/auth/applications", appData, auth)
    .then((r) => {console.log(r);})
    .catch((e) => {console.error(e)});
API.post("/user_schemas", userSchema, auth)
    .then((r) => {console.log(r);})
    .catch((e) => {console.error(e)});
API.post("/repositories", repoSBox, auth)
    .then((r) => {console.log(r); dataId = r.data.repository.repository_id})
    .then(() => API.post("/repositories", repoOther, auth))
    .then((r) => {console.log(r); otherId = r.data.repository.repository_id})
    .then(() => API.post(`/repositories/${otherId}/schemas`, usbox, auth))
    .then((r) => {console.log(r); return API.post(`/repositories/${otherId}/schemas`, pubKeys, auth)})
    .then((r) => {console.log(r); return API.post(`/repositories/${dataId}/schemas`, sbox, auth)})
    .then((r) => {console.log(r); return API.post(`/repositories/${dataId}/schemas`, ks, auth)})
    .then((r) => {console.log(r); return API.post(`/repositories/${dataId}/schemas`, sbm, auth)})
    .then((r) => {console.log(r); return API.post(`/repositories/${dataId}/schemas`, sbf, auth)})
    .catch((e) => {console.error(e)});
