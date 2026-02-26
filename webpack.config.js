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
    extensions: ['.tsx', '.ts', '.js'],
  },
  output: {
    path: path.resolve(__dirname, 'dist/min'),
    library: {
      name: 'WavesCrypto',
      type: 'umd',
    },
    globalObject: 'this',
    filename: 'waves-lib-crypto.js',
  },
}
