"use script"

/*
   This script is meant for creating
   required data structures on Chino server

   Note: this script will remove everything is on your space on Chino Server
*/

const API = require("./lib/api_connect");

const auth = {
  id    : process.env.CHINO_ID,   // change with your Chino Customer ID
  secret: process.env.CHINO_KEY   // change with your Chino Customer Key
}

const cleanTheEnvironment = true; // decide if clean your Chino environment

/* NEEDED STRUCTURES */
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
  description: "User SBoxes",
  structure: {
    fields: [
      {
        name: "user_id",
        type: "string",
        indexed: true
      },
      {
        name: "sbox_id",
        type: "string",
        indexed: true
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

/* Needs to be created dynamically when a new SBox document is created */
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
  description: "SBox Documents",
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
        type: "string"
      },
      {
        name: "ad",
        type: "json"
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
        type: "datetime",
        indexed: true
      },
      {
        name: "uploader_id",
        type: "string"
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
}

/* DELETE EVERYTHING ON CHINO - IF REQUIRED */
if (cleanTheEnvironment) {
  Promise.all([
    API.get(`/auth/applications`, {}, auth)
        .then(result =>
            Promise.all(result.data.applications.map(
                app => API.del(`/auth/applications/${app.app_id}`, {}, auth)
                )
            )
        )
        .then((result) => {
          result.forEach(res => console.log(res.result_code));
        }),
    API.get(`/collections`, {}, auth)
        .then(result =>
            Promise.all(result.data.collections.map(
                c => API.del(`/collections/${c.collection_id}`, {force:true}, auth)
                )
            )
        )
        .then((result) => {
          result.forEach(res => console.log(res.result_code));
        }),
    API.get(`/groups`, {}, auth)
        .then(result =>
            Promise.all(result.data.groups.map(g => API.del(`/groups/${g.group_id}`, {force:true}, auth)))
        )
        .then((result) => {
          result.forEach(res => console.log(res.result_code));
        }),
    API.get(`/repositories`, {}, auth)
        .then(result =>
            Promise.all(
                result.data.repositories.map(
                    repo => API.get(`/repositories/${repo.repository_id}/schemas`, {offset : 0, limit : 50}, auth)
                        .then(res => Promise.all(res.data.schemas.map(
                            schema => API.del(`/schemas/${schema.schema_id}`, {force : true, all_content : true}, auth)))
                        )
                        .then(res => API.del(`/repositories/${repo.repository_id}`, {force:true}, auth))
                        .catch(err => console.log(err))
                )
            )
        )
        .then((result) => {
          result.forEach(res => console.log(res.result_code));
        }),
    API.get(`/user_schemas`, {}, auth)
        .then(result =>
            Promise.all(
                result.data.user_schemas.map(
                    us => API.del(`/user_schemas/${us.user_schema_id}`, {force:true}, auth)
                )
            )
        )
        .then((result) => {
          result.forEach(res => console.log(res.result_code));
        })
  ])
      .then(() => {console.log("Chino environment cleaned"); return uploadStructure() })
      .catch(error => { console.log(error); });
}
else {
  uploadStructure();
}

// CALLS
function uploadStructure() {
  return Promise.all([
    API.post("/auth/applications", appData, auth)
        .then((r) => {console.log(r);}),
    API.post("/user_schemas", userSchema, auth)
        .then((r) => {console.log(r);}),
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
  ])
      .then(() => console.log("\nNeeded data structures successfully created on Chino server"))
      .catch((e) => {console.error(e)});
}
