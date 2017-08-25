/**
 * This file contains the methods for connecting to Chino API
 * */
"use strict";

const request = require("superagent");

/** Manage response from Chino API
 *
 * @param error      The possible error object that can be returned
 * @param response   The response object returned from Chino server
 * @ignore
 */
function responseHandler(error, response) {
  if (error) {
    this.reject(response.body || error);
  }
  else {
    this.resolve(response.body);
  }
}

function checkUrl(url) {
  return url.startsWith("/") ? url : `/${url}`;
}

class Call {
  // String constants for /auth/token API
  static get GRANT_TYPES() {
    return {
      PASSWORD : "password",
      RFS_TOKEN : "refresh_code",
      REVOKE : "revoke"
    }
  }
  // content types for HTTP methods
  static get CONT_TYPES() {
    return {
      JSON : "application/json",
      FORM_DATA : "multipart/form-data",
      OCT_STREAM : "application/octet-stream"
    }
  }

  static get BASE_URL() {
    return "https://api.test.chino.io/v1";
  }

  /** Make GET request to specified url
   *
   * @param url     {string} The selected {string} The selected Chino API url
   * @param params  {Object} A object containing parameters to be added to the request
   * @param auth    {Object} A object representing authentication info for Chino server
   * @return {Promise}
   */
  static get(url, params = {}, auth = null) {
    url = checkUrl(url);

    let makeCall = (resolve, reject) => {
      // set request settings
      const req = request.get(Call.BASE_URL + url)
                         .type("application/json")
                         .accept("application/json")
                         .query(params);
      // if needed by user set request authentication
      if (auth && auth["id"] && auth["secret"]) {
        req.auth(auth.id, auth.secret);
      }
      // send the request
      req.end(responseHandler.bind({resolve, reject}));
    }

    return new Promise(makeCall);
  }

  /** Make GET request to specified url
   *  to retrieve blob data
   *
   * @param url     {string} The selected Chino API url
   * @param params  {Object} A object containing parameters to be added to the request
   * @param auth    {Object} A object representing authentication info for Chino server
   * @return  {Promise}
   */
  static getBlob(url, params = {}, auth = null) {
    url = checkUrl(url);

    let makeCall = (resolve, reject) => {
      const req = request.get(Call.BASE_URL + url)
                         .type("application/json")
                         .query(params)
                         .accept("application/octet-stream")
                         .responseType("arraybuffer");

      if (auth && auth["id"] && auth["secret"]) {
        req.auth(auth.id, auth.secret);
      }
      req.end(responseHandler.bind({resolve, reject}));
    }

    return new Promise(makeCall);
  }

  /** Make POST request to specified url
   *
   * @param url         {string} The selected Chino API url
   * @param data        {Object} The data that will be sent with the request
   * @param acceptType  {string | null} The MIME type used for the request
   * @param auth        {Object} A object representing authentication info for Chino server
   * @return {Promise}
   */
  static post(url, data = {}, auth = null, acceptType = null) {
    url = checkUrl(url);

    let makeCall = (resolve, reject) => {
      // prepare the request and then send it
      const req = request.post(Call.BASE_URL + url);

      // error data in used in case of data is empty or miss any property
      const missingFieldException = {
        message : "Trying to make request with wrong or empty data",
        result_code : 400,
        result : "error",
        data : null
      };

      if (acceptType === Call.CONT_TYPES.FORM_DATA) {
/*        req.set("Content-Type", "multipart/form-data")
           .accept("multipart/json")
           .auth("68df40b2-b006-4a56-8b28-e965a80e76f7", "3a5f35a7-3afc-4a64-af45-7fcc7423f589");*/

        // set form fields
        switch (data["grant_type"]) {
          case Call.GRANT_TYPES.PASSWORD:
            if (data["username"] && data["password"] && data["client_id"]) {
              req
                  .field("grant_type", "password")
                  .field("username", data["username"])
                  .field("password", data["password"])
                  .field("client_id", data["client_id"])
            }
            else {
              throw missingFieldException;
            }
            break;
          case Call.GRANT_TYPES.RFS_TOKEN:
            if (data["refresh_token"] && data["client_id"]) {
              req
                  .field("grant_type", "refresh_token")
                  .field("refresh_token", data["refresh_token"])
                  .field("client_id", data["client_id"])
            }
            else {
              throw missingFieldException;
            }
            break;
          case Call.GRANT_TYPES.REVOKE:
            if (data["token"] && data["client_id"]) {
              req
                  .field("token", data["token"])
                  .field("client_id", data["client_id"])
            }
            else {
              throw missingFieldException;
            }
            break;
          default:
            throw {
              message : "No grant type selected",
              result_code : 400,
              result : "error",
              data : null
            };
        }
      }
      else {
        if (auth && auth["id"] && auth["secret"]) {
          req.auth(auth.id, auth.secret);
        }

        req.type("application/json")
           .accept("application/json")
           .send(data);
      }

      req.end(responseHandler.bind({resolve, reject}));
    }

    return new Promise(makeCall);
  }

  /** Make PUT request to specified url
   *
   * @param url     {string} The selected Chino API url
   * @param data    {Object} The data that will be sent with the request
   * @param params  {Object} A object containing parameters to be added to the request
   * @param auth    {Object} A object representing authentication info for Chino server
   * @return {Promise}
   */
  static put(url, data = {}, params = {}, auth = null) {
    url = checkUrl(url);

    let makeCall = (resolve, reject) => {
      const req = request.put(Call.BASE_URL + url)
                         .type("application/json")
                         .accept("application/json")
                         .send(data);
      if (auth && auth["id"] && auth["secret"]) {
        req.auth(auth.id, auth.secret);
      }
      req.end(responseHandler.bind({resolve, reject}));
    }

    return new Promise(makeCall);
  }

  /** Make PUT request to specified url
   *  sending data as octet stream
   *
   * @param url     {string} The selected Chino API url
   * @param data    {Object} The data that will be sent with the request
   * @param params  {Object} A object containing parameters to be added to the request
   * @param auth    {Object} A object representing authentication info for Chino server
   * @return {Promise}
   */
  static chunk(url, data = {}, params = {}, auth = null) {
    url = checkUrl(url);

    let makeCall = (resolve, reject) => {
      const req = request.put(Call.BASE_URL + url)
          /*.use(throttle.plugin(url))*/
                         .set("offset", params.blob_offset)
                         .set("length", params.blob_length)
                         .type("application/octet-stream")
                         .accept("application/json")
                         .send(data);
      if (auth && auth["id"] && auth["secret"]) {
        req.auth(auth.id, auth.secret);
      }
      req.end(responseHandler.bind({resolve, reject}));
    }

    return new Promise(makeCall);
  }

  /** Make PATCH request to specified url
   *
   * @param url     {string} The selected Chino API url
   * @param data    {Object} The data that will be sent with the request
   * @param auth    {Object} A object representing authentication info for Chino server
   * @return {Promise}
   */
  static patch(url, data = {}, auth = null) {
    url = checkUrl(url);

    let makeCall = (resolve, reject) => {
      const req = request.patch(Call.BASE_URL + url)
                         .type("application/json")
                         .accept("application/json")
                         .send(data);
      if (auth && auth["id"] && auth["secret"]) {
        req.auth(auth.id, auth.secret);
      }
      req.end(responseHandler.bind({resolve, reject}));
    }

    return new Promise(makeCall);
  }


  /** Make DELETE request to specified url
   *
   * @param url     {string} The selected Chino API url
   * @param params  {Object} A object containing parameters to be added to the request
   * @param auth    {Object} A object representing authentication info for Chino server
   * @return {Promise}
   */
  static del(url, params = {}, auth = null) {
    url = checkUrl(url);

    let makeCall = (resolve, reject) => {
      const req = request.del(Call.BASE_URL + url)
          .type("application/json")
          .accept("application/json")
          .query(params);
      if (auth && auth["id"] && auth["secret"]) {
        req.auth(auth.id, auth.secret);
      }
      req.end(responseHandler.bind({resolve, reject}));
    }

    return new Promise(makeCall);
  }
}

module.exports = Call;