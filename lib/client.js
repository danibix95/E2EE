"use strict";

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
 removeSecurityBox(sbox_id) -> result
 deleteAccount() -> result
 search(username) -> user_id
 sync() -> list_of_conversation_ids
 */


/* Private/Public key -> saved in the session storage
*
* */