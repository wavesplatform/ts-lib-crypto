// webpack.config.js
const path = require('path')

module.exports = {
  entry: './src/index.ts',
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    alias: {
      '@noble/curves/bls12-381': '@noble/curves/bls12-381.js',
      '@noble/hashes/hkdf': '@noble/hashes/hkdf.js',
      '@noble/hashes/sha2': '@noble/hashes/sha2.js',
      '@noble/curves/utils': '@noble/curves/utils.js',
    },
    extensions: ['.tsx', '.ts', '.js'],
  },
  output: {
    path: path.resolve(__dirname, 'dist/min'),
    library: 'WavesCrypto',
    libraryTarget: 'umd',
    filename: 'waves-lib-crypto.js',
  },
}
