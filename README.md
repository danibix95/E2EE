# E2EE
Client-side library for providing a end to end encryption service using Chino API


## How to test this repository

Requirements: [Node.js](https://nodejs.org), you can use [NVM](https://github.com/creationix/nvm/blob/master/README.md) to install it.

Clone the repository:

    git clone https://github.com/danibix95/E2EE.git
    
And enter inside project folder

    cd E2EE

Then edit the following two files and insert your Chino Customer credentials:

- [genDataStructures.js (L12)](https://github.com/danibix95/E2EE/blob/dev/genDataStructures.js#L12)

      const auth = {
          id    : <CHINO_ID>,   // change with your Chino Customer ID
          secret: <CHINO_KEY>   // change with your Chino Customer Key
      }
- [test/test.e2.ee.js (L17)](https://github.com/danibix95/E2EE/blob/master/test/test.e2ee.js#L17)

      const credentials = {
        id: <CHINO_ID>,         // change with your Chino Customer ID
        secret: <CHINO_KEY>     // change with your Chino Customer Key
      }
Now it is possible to initialize the environment.  
**Warning:** genDataStructure script will delete everything you have on your Chino space.

    npm install
    npm run dist
    node genDataStructures

After last operation it is possible to copy the output of `genDataStructure` into the test file, in order to correctly initialize the library environment.

Example of output from `genDataStructure`:

    sboxRepo: 'c4c3433b-1167-49ee-8d69-60a5a1b772cd',
    sboxSchema: '955e32a8-4b70-4782-bb5e-6831c7bcefd7',
    keysSchema: 'f36df8bd-c5ef-421c-abb2-7ae9d0df931d',
    linkSchema: '26920e50-e9de-4b2b-a430-5dd86cbc6f27',
    keysGroup: 'ff9503b9-298f-468b-bc35-a04326cf3858',
    userSchema: 'c27a09cb-d3ea-4e3c-93ee-ba27f8c6ede5',
    appId: 'esvqVKWzzzqfpUb0qItV6UYkUK65iqg0SDoKmkZg'
    
It needs to be copied in [test/test.e2.ee.js (L6-12)](https://github.com/danibix95/E2EE/blob/master/test/test.e2ee.js#L6-L12)

Finally it is possible to test the library. Open in your browser (*Google Chrome or Firefox is preferred for working with Web Crypto API*), select the file `test/data.txt` from file chooser e press the button `Run tests` for starting testing the library.