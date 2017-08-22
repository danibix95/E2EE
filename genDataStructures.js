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
        name: "name",
        type: "string",
        indexed: true
      },
      {
        name: "keys",
        type: "string",
        indexed: true
      },
      {
        name: "documents",
        type: "string",
        indexed: true
      },
      {
        name: "files",
        type: "string",
        indexed: true
      },
      {
        name: "group",
        type: "string",
        indexed: true
      }
    ]
  }
}

const groupInfo = {
  group_name: "Default group",
  attributes: {}
}

console.log("Execution started on:", new Date(), "\n");
/* DELETE EVERYTHING ON CHINO - IF REQUIRED */
if (cleanTheEnvironment) {
  console.log("Clean Chino environment:");
  Promise.all([
    API.get(`/auth/applications`, {}, auth)
        .then(result =>
            Promise.all(result.data.applications.map(
                app => API.del(`/auth/applications/${app.app_id}`, {}, auth)
                )
            )
        )
        .then((result) => {
          result.forEach(res => process.stdout.write("\u2713"));
        }),
    API.get(`/collections`, {}, auth)
        .then(result =>
            Promise.all(result.data.collections.map(
                c => API.del(`/collections/${c.collection_id}`, {force:true}, auth)
                )
            )
        )
        .then((result) => {
          result.forEach(res => process.stdout.write("\u2713"));
        }),
    API.get(`/groups`, {}, auth)
        .then(result =>
            Promise.all(result.data.groups.map(g => API.del(`/groups/${g.group_id}`, {force:true}, auth)))
        )
        .then((result) => {
          result.forEach(res => process.stdout.write("\u2713"));
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
          result.forEach(res => process.stdout.write("\u2713"));
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
          result.forEach(res => process.stdout.write("\u2713"));
        })
  ])
      .then(() => {
        console.log("\nChino environment cleaned!\n\nCreate data structures:");
        return uploadStructure()
      })
      .catch(error => { console.log(error); });
}
else {
  uploadStructure();
}

// CALLS
function uploadStructure() {
  const options = {
    sboxRepo : null,
    sboxSchema : null,
    keysSchema : null,
    linkSchema : null,
    keysGroup : null,
    userSchema : null,
    appId : null
  }
  return Promise.all([
    API.post("/auth/applications", appData, auth)
        .then((r) => {process.stdout.write("."); options.appId = r.data.application.app_id}),
    API.post("/user_schemas", userSchema, auth)
        .then((r) => {process.stdout.write("."); options.userSchema = r.data.user_schema.user_schema_id}),
    API.post("/repositories", repoSBox, auth)
        .then((r) => {
          options.sboxRepo = r.data.repository.repository_id
          process.stdout.write(".");

          return API.post("/repositories", repoOther, auth);
        })
        .then((r) => {
          otherId = r.data.repository.repository_id
          process.stdout.write(".");

          return API.post(`/repositories/${otherId}/schemas`, usbox, auth);
        })
        .then((r) => {
          options.linkSchema = r.data.schema.schema_id;
          process.stdout.write(".");

          return API.post(`/repositories/${otherId}/schemas`, pubKeys, auth)
        })
        .then((r) => {
          options.keysSchema = r.data.schema.schema_id;
          process.stdout.write(".");

          return API.post(`/repositories/${options.sboxRepo}/schemas`, sbox, auth)
        })
        .then((r) => {
          options.sboxSchema = r.data.schema.schema_id;
          process.stdout.write(".");

          return API.post(`/groups`, groupInfo, auth);
        })
        .then((r) => {
          options.keysGroup = r.data.group.group_id;
          process.stdout.write(".");
          console.log("Done\n\nAssign Permissions:")
          // set permissions for this group
          return Promise.all([
            API.post(
                `/perms/grant/groups/groups/${options.keysGroup}`,
                {
                  manage : ["C", "R", "D"],
                  authorize : ["C", "R", "D", "A"]
                },
                auth
            )
            .then(() => process.stdout.write("\u2713"))
            .catch((e) => { process.stdout.write("1\u2717"); console.log(e) }),
            API.post(
                `/perms/grant/repositories/${options.sboxRepo}/schemas/groups/${options.keysGroup}`,
                {
                  manage : ["C", "U", "R", "D", "L"],
                  authorize : ["C", "U", "R", "D", "L", "A"]
                },
                auth
            )
            .then(() => process.stdout.write("\u2713"))
            .catch((e) => { process.stdout.write("2\u2717"); console.log(e) }),
            API.post(
                `/perms/grant/schemas/${options.sboxSchema}/documents/groups/${options.keysGroup}`,
                {
                  manage : ["C", "R", "D", "S", "L"],
                  authorize : ["C", "R", "D", "S", "L", "A"],
                  created_document: {
                    manage : ["R", "D"],
                    authorize : ["R", "D", "A"]
                  }
                },
                auth
            )
            .then(() => process.stdout.write("\u2713"))
            .catch((e) => { process.stdout.write("3\u2717"); console.log(e) }),
            API.post(
                `/perms/grant/schemas/${options.keysSchema}/documents/groups/${options.keysGroup}`,
                {
                  manage : ["C", "R", "D", "S"],
                  authorize : ["C", "R", "D", "S", "A"],
                  created_document: {
                    manage : ["R", "D"],
                    authorize : ["R", "D", "A"]
                  }
                },
                auth
            )
            .then(() => process.stdout.write("\u2713"))
            .catch((e) => { process.stdout.write("4\u2717"); console.log(e) }),
            API.post(
                `/perms/grant/schemas/${options.linkSchema}/documents/groups/${options.keysGroup}`,
                {
                  manage : ["C", "R", "D", "S"],
                  authorize : ["C", "R", "D", "S", "A"],
                  created_document: {
                    manage : ["R", "D"],
                    authorize : ["R", "D", "A"]
                  }
                },
                auth
            )
            .then(() => process.stdout.write("\u2713"))
            .catch((e) => { process.stdout.write("5\u2717"); console.log(e) }),
          ])
        })
  ])
      .then(() => {
        console.log("\n\nNeeded data structures successfully created on Chino server!");
        console.log("\nUse following settings to initialize the library client:\n");
        console.log(options);
        console.log();
      })
      .catch((e) => {console.error(e)});
}
