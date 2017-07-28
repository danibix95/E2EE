const path = require('path');
const webpack = require('webpack');

module.exports = {
  entry: './index.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'e2ee.js',
    libraryTarget: 'window',
    library: 'SBOX'
  }
};