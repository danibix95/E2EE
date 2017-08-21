"use strict";

// WARNIGN: place here your settings
const client = window.E2EE(
{
  sboxRepo: '51dca3aa-2bd1-4c14-b4a3-f6db9347f7b3',
  sboxSchema: 'b0765f86-32ee-4ca7-8b0f-05425aa26ac4',
  keysSchema: '0c34d4bf-1622-4032-b8ce-78a603623b3f',
  linkSchema: '9c9c899a-5bce-4840-83ae-d4c1f8f7c223',
  keysGroup: '70ae2418-a403-4fe0-ab62-86ea48211241',
  userSchema: '9f365964-9877-40ad-a0d7-115fa11faa00',
  appId: 'yzaI3nKoDGyZ0vuBZBwym96vrp5YmVhptV3oOa4q'
}
)

// place here your customer credentials for testing user management
const credentials = {
  id: "",
  secret: ""
}

describe("End To End Encryption Library Test", function() {
  this.slow(300);
  // change timeout for slow network
  this.timeout(5000);

  let User = client.User;
  let SBox = client.SBox;

  const username = `daniele${new Date().getTime()}`;
  let user1;

  // doc to be inserted into SBox
  const doc = {
    title: "My first message",
    content: "This is an important message!"
  }

  describe("User class - Part 1", function () {
    beforeEach(function (done) {
      // wait enough time that things are ready to be searched
      setTimeout(() => {done()}, 800);
    });

    it("Sign Up", function() {
      return User.signUp(username, "hello1234", "space3design", {}, {}, credentials)
          .then((result) => result.should.be.equal(true));
    });

    it("Login", function() {
      return User.login(username, "hello1234", "space3design", {})
          .then((result) => {
            result.should.be.instanceof(User);
            should.not.exists(result.auth);
            should.not.exists(result.refreshToken);
            should.not.exists(result.userId);
            should.not.exists(result.sboxes);

            // save user object for later
            user1 = result;
          });
    });

    it("Update Token", function() {
      return user1.updateAuth()
          .then((result) => {
            result.should.be.instanceof(Number);
            result.should.be.above(0);
          })
    });

    it("Username Search", function() {
      return User.search(username)
          .then((result) => {
            result.should.be.instanceof(String);
            result.should.be.equal(user1.userId);
          })
    });

    it("Create SBox", function() {
      this.timeout(10000);

      return user1.createSBox("My First SBox")
          .then((result) => result.should.be.equal(true));
    });
  });

  describe("SBox class", function () {
    it("Insert document", function() {
      return sbox.insert(user1, doc, {})
          .then((result) => {
            should.be.equal(true);
          })

    });

    it("Insert file", function() {
      return new Promise((resolve, reject) => resolve(1));
    });

    it("Read document", function() {
      return sbox.retrieve(user1)
          .then((result) => {

          });
    });

    it("Read file", function() {
      return new Promise((resolve, reject) => resolve(1));

    });

    it("Grant permissions", function() {
      return new Promise((resolve, reject) => resolve(1));

    });

    it("Revoke permissions", function() {
      return new Promise((resolve, reject) => resolve(1));

    });

    it("Delete document", function() {
      return new Promise((resolve, reject) => resolve(1));

    });

    it("Delete file", function() {
      return new Promise((resolve, reject) => resolve(1));

    });
  });

  describe("User class - Part 2", function () {
    it("Delete SBox", function() {
      return new Promise((resolve, reject) => resolve(1));

    });

    it("Delete Account", function() {
      return new Promise((resolve, reject) => resolve(1));

    });
  });
});