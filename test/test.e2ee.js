"use strict";

// WARNIGN: place here your settings
const client = window.E2EE(
{
  sboxRepo: 'a61a29dd-7e74-4de4-9931-2b4d26a52add',
  sboxSchema: '50d1023f-5916-43a1-ba5a-971396ead338',
  keysSchema: '31c53733-cef9-4b96-9f17-bcef92ff86a6',
  linkSchema: '4a1a5c04-1a96-46ce-adb9-a0d5e596d27b',
  keysGroup: '309377e5-cb52-40c3-9e1e-555412865f1d',
  userSchema: '7e25e444-9ef3-4e3a-ae90-e24f37348273',
  appId: 'BUik3M8hO8dSc0hBSf6sNaxXUbmzSW4nukVVsxY5'
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
  const chinoPwd = "hello1234";
  const e2ePwd = "space3design";
  let user1 = null;
  let user2 = null;
  let sbox1 = null;
  // name of the file to upload
  let filename = "";
  // ids
  let doc1 = "";
  let file1 = "";

  // doc to be inserted into SBox
  const docToEncrypt = {
    title: "My first message",
    content: "This is an important message!"
  }

  describe("User class - Part 1", function () {
    beforeEach(function (done) {
      // wait enough time that things are ready to be searched
      setTimeout(() => {
        done()
      }, 800);
    });

    it("Sign Up", function () {
      return User.signUp(username, chinoPwd, e2ePwd, {}, {}, credentials)
          .then((result) => result.should.be.equal(true));
    });

    it("Login", function () {
      return User.login(username, chinoPwd, e2ePwd, {})
          .then((result) => {
            result.should.be.instanceof(User);
            should.not.exists(result.auth);
            should.not.exists(result.refreshToken);
            should.not.exists(result.sboxes);
            should.exists(result.userId);
            should.exists(result.username);
            result.username.should.be.equal(username);

            // save user object for later
            user1 = result;
          });
    });

    it("Update Token", function () {
      return user1.updateAuth()
          .then((result) => {
            result.should.be.instanceof(Number);
            result.should.be.above(0);
          })
    });

    it("Username Search", function () {
      return user1.search(username)
          .then((result) => {
            result.should.be.instanceof(String);
            result.should.be.equal(user1.userId);
          })
    });

    it("Create SBox", function () {
      this.timeout(10000);

      return user1.createSBox("My First SBox")
          .then((result) => result.should.be.equal(true));
    });

    it("Get user's SBox", function () {
      user1.sboxesId.should.be.instanceof(Iterable);
      user1.sboxesId.length.should.be.above(0);

      sbox1 = user1.getSBox(user1.sboxesId[0]);
    });
  });

  describe("SBox class - part 1", function () {
    it("Insert document", function () {
      return sbox1.insert(user1, docToEncrypt, {})
          .then((result) => {
            result.should.be.equal(true);
          });
    });

    it("Insert file", function () {
      if (!fileToUpload.length || fileToUpload.length > 1)
        throw new Error("No file or too much files are provided for uploading!");

      filename = fileToUpload[0].name;

      return sbox1.insertFile(user1, fileToUpload[0], {})
          .then((result) => {
            result.should.be.equal(true);
          });
    });

    it("Grant permissions", function () {
      return sbox1.grantAccess(user1, user2.username)
          .then((result) => {
            result.should.be.equal(true);
          });
    });
  });

  describe("SBox class - part 2 - other user access", function () {
    it("Test logout feature and create a new user", function () {
      return user1.logout()
          .then((result) => { result.should.be.equal(true); })
          .then(() => User.signUp("dummyUser", chinoPwd, "dummyPassword", {}, {}, credentials))
          .then(() => User.login("dummyUser", chinoPwd, "dummyPassword", {}))
          .then((result) => {
            user2 = result;
          });
    });

    it("Test user synchronization", function () {
      return sbox1.syncUsers()
          .then((result) => { result.should.be.equal(true); });
    });

    it("Test SBox synchronization", function () {
      return user2.syncSBoxes()
          .then((result) => { result.should.be.equal(true); });
    });

    it("Retrieves all the SBox documents", function () {
      return sbox.retrieve(user2)
          .then((result) => {
            result.should.be.instanceof(Array);
            result.length.should.be.above(0);
            should.exists(result[0].id);
            should.exists(result[0].data);
            should.exists(result[0].timestamp);

            should.be.deepEqual(result[0].data, docToEncrypt);

            doc1 = result[0].id;
          });
    });

    it("Retrieves all the SBox documents uploaded after last download,", function () {
      return sbox.retrieve(user2, new Date(new Date().setMinutes(-1)))
          .then((result) => {
            result.should.be.instanceof(Array);
            result.length.should.be.above(0);
            should.exists(result[0].data);
            should.exists(result[0].timestamp);

            should.be.deepEqual(result[0].data, docToEncrypt);
          });
    });

    it("Retrieves all the SBox files", function () {
      return sbox.retrieveFiles(user2)
          .then((result) => {
            result.should.be.instanceof(Array);
            result.length.should.be.above(0);

            should.exists(result[0].id);
            result[0].should.be.instanceof(Uint8Array);
            new File(result[0].blob, filename).should.be.equal(fileToUpload[0]);

            file1 = result[0].id;
          });
    });

    it("Retrieves all the SBox files uploaded after last download", function () {
      return sbox.retrieveFiles(user2, new Date(new Date().setMinutes(-1)))
          .then((result) => {
            result.should.be.instanceof(Array);
            result.length.should.be.above(0);

            should.exists(result[0].id);
            result[0].blob.should.be.instanceof(Uint8Array);
            new File(result[0].blob, filename).should.be.equal(fileToUpload[0]);
          });
    });
  });

  describe("SBox class - part 3 - remove data", function () {
    it("Log out dummy user and login first user", function () {
      return user2.logout()
          .then(() => User.login(username, chinoPwd, e2ePwd))
          .then((result) => { user1 = result; });
    })

    it("Revoke permissions", function() {
      return sbox1.revokeAccess(user1, user2.username)
          .then((result) => { result.should.be.equal(true); });
    });

    it("Delete document", function() {
      return sbox1.remove(doc1, user1)
          .then((result) => { result.should.be.equal(true); });
    });

    it("Delete file", function() {
      return sbox1.removeFile(file1, user1)
          .then((result) => { result.should.be.equal(true); });
    });
  });

  describe("User class - Part 2", function () {
    it("Delete SBox", function() {
      return user1.removeSBox(sbox1.id)
          .then((result) => { result.should.be.equal(true); });
    });

    it("Delete Account", function() {
      return user1.deleteAccount()
          .then((result) => { result.should.be.equal(true); });
    });
  });
});