"use strict"

const crypto = require('crypto');
const hash = crypto.createHash('sha256');

self.addEventListener('message', function(e) {
  hash.update(e.data);
  postMessage(hash.digest('base64'));
}, false);

// self.close();