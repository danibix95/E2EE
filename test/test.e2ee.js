"use strict";

// WARNIGN: place here your settings
const client = window.E2EE(
{
  sboxRepo: '09776831-274d-486a-a1d0-e0f36dbd44ee',
  sboxSchema: '463c2cd0-c52b-4cb9-8804-a05611c4d6de',
  keysSchema: '500f2d11-c0bf-42ef-86cf-5c9df0305435',
  linkSchema: '304c18dc-613e-4899-96dc-89aed1f903b4',
  keysGroup: '9adf4253-4169-4db6-ac04-8621c3b1842d',
  userSchema: '337f85a1-ca80-4b33-bdff-146bf72d05b5',
  appId: 'eLpJLhjXcKpUkB9wtNEvLlVPppRUapuAD0VOetJk'
}
)

describe("End To End Encryption Library Test", function() {
  this.slow(300);
  // change timeout for slow network
  this.timeout(5000);

  let User = client.User;
  let SBox = client.SBox;

  const username = `daniele${new Date().getTime()}`;
  const secondUser = `User2-${new Date().getTime()}`;
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
          .then((result) => result.should.be.equal(true))
          /* sign up also a second user */
          .then(() => User.signUp(secondUser, chinoPwd, "dummyPassword", {}, {}, credentials));
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
      user1.sboxesId.should.be.instanceof(Object);
      const sboxId = user1.sboxesId.next().value;
      should.exists(sboxId); // at least one element

      sbox1 = user1.getSBox(sboxId);
      should.exists(sbox1);
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
      return new Promise((resolve, reject) => {
        setTimeout(() => {
          resolve();
        }, 800);
      })
      .then(() => sbox1.grantAccess(user1, secondUser))
      .then((result) => {
        result.should.be.equal(true);
      });
    });
  });

  describe("SBox class - part 2 - other user access", function () {
    it("Test logout feature and create a new user", function () {
      return user1.logout()
          .then((result) => { result.should.be.equal(true); })
          .then(() => User.login(secondUser, chinoPwd, "dummyPassword", {}))
          .then((result) => {
            user2 = result;
          });
    });

    it("Test user synchronization", function () {
      return sbox1.syncUsers(user2)
          .then((result) => { result.should.be.equal(true); });
    });

    it("Test SBox synchronization", function () {
      return user2.syncSBoxes()
          .then((result) => { result.should.be.equal(true); });
    });

    it("Retrieves all the SBox documents", function () {
      return sbox1.retrieve(user2)
          .then((result) => {
            result.should.be.instanceof(Array);
            result.length.should.be.above(0);
            should.exists(result[0].id);
            should.exists(result[0].data);
            should.exists(result[0].timestamp);

            should(result[0].data).deepEqual(docToEncrypt);

            doc1 = result[0].id;
          });
    });

    it("Retrieves all the SBox documents uploaded after last download,", function () {
      return sbox1.retrieve(user2, new Date(new Date().setMinutes(-1)))
          .then((result) => {
            result.should.be.instanceof(Array);
            result.length.should.be.above(0);
            should.exists(result[0].data);
            should.exists(result[0].timestamp);

            should(result[0].data).deepEqual(docToEncrypt);
          });
    });

    it.skip("Retrieves all the SBox files", function () {
      this.timeout(10000);
      return sbox1.retrieveFiles(user2)
          .then((result) => {
            result.should.be.instanceof(Array);
            result.length.should.be.above(0);

            should.exists(result[0].id);
            result[0].should.be.instanceof(Uint8Array);
            new File(result[0].blob, filename).should.be.equal(fileToUpload[0]);

            file1 = result[0].id;
          });
    });

    it.skip("Retrieves all the SBox files uploaded after last download", function () {
      this.timeout(10000);
      return sbox1.retrieveFiles(user2, new Date(new Date().setMinutes(-1)))
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

    it.skip("Delete file", function() {
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