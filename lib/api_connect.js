/**
 * This file contains the methods for connecting to Chino API
 * */
"use strict";

const request = require("superagent");
const binaryParser = require("superagent-binary-parser");

/** Manage response from Chino API
 *
 * @param error      The possible error object that can be returned
 * @param response   The response object returned from Chino server
 */
function responseHandler(error, response) {
  if (error) {
    this.reject(response.body || error);
  }
  else {
    this.resolve(response.body);
  }
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
   * @param url         {string}
   * @param params      {object}
   * @return {Promise}
   */
  static get(url, params = {}, auth = undefined) {
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
   * @param url         {string}
   * @param params      {object}
   * @return  {request}
   */
  static getBlob(url, params = {}, auth = undefined) {
    const req = request.get(Call.BASE_URL + url)
                       .type("application/json")
                       .accept("application/octet-stream")
                       .query(params)
                       .buffer(true);
    if (auth && auth["id"] && auth["secret"]) {
      req.auth(auth.id, auth.secret);
    }
    return req.parse(binaryParser);
  }

  /** Make POST request to specified url
   *
   * @param url         {string}
   * @param data        {object}
   * @param acceptType  {string | null}
   * @return {Promise}
   */
  static post(url, data = {}, auth = undefined, acceptType = null) {
    let makeCall = (resolve, reject) => {
      // prepare the request and then send it
      const req = request.post(Call.BASE_URL + url)

      // error data in used in case of data is empty or miss any property
      const missingFieldException = {
        message : "Trying to make request with wrong or empty data",
        result_code : 400,
        result : "error",
        data : null
      };

      if (acceptType === Call.CONT_TYPES.FORM_DATA) {
        req.set("Content-Type", "multipart/form-data")
           .accept("multipart/json");

        // set form fields
        switch (data["grant_type"]) {
          case Call.GRANT_TYPES.PASSWORD:
            if (data["username"] && data["password"]) {
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
            if (data["token"] && data["client_id"] && data["client_secret"]) {
              req
                  .field("grant_type", "refresh_token")
                  .field("refresh_token", data["token"])
                  .field("client_id", data["client_id"])
                  .field("client_secret", data["client_secret"])
            }
            else {
              throw missingFieldException;
            }
            break;
          case Call.GRANT_TYPES.REVOKE:
            if (data["token"] && data["client_id"] && data["client_secret"]) {
              req
                  .field("token", data["token"])
                  .field("client_id", data["client_id"])
                  .field("client_secret", data["client_secret"])
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
   * @param url         {string}
   * @param data        {object}
   * @param params      {object}
   * @return {Promise}
   */
  static put(url, data = {}, params = {}, auth = undefined) {
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
   * @param url         {string}
   * @param data        {object}
   * @param params      {object}
   * @return {Promise}
   */
  static chunk(url, data = {}, params = {}, auth = undefined) {
    // manage concurrency calls
    // let throttle = new sThrottle({
    //   active: true,
    //   rate: 5,
    //   ratePer: 40000,
    //   concurrent: 5
    // });

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
   * @param url   {string}
   * @param data  {object}
   * @return {Promise}
   */
  static patch(url, data = {}, auth = undefined) {
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
   * @param url     {string}
   * @param params  {object}
   * @return {Promise}
   */
  static del(url, params = {}, auth = undefined) {
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