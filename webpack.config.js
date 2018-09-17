const webpack = require('webpack')
const copy = require('copy-webpack-plugin')
const path = require('path')
const fs = require('fs')

const deleteFolder = (folderPath) => {
  if (fs.existsSync(folderPath)) {
    fs.readdirSync(folderPath).forEach((file) => {
      const curPath = path.resolve(folderPath, file)
      fs.statSync(curPath).isDirectory() ?
        deleteFolder(curPath) :
        fs.unlinkSync(curPath)
    })
    fs.rmdirSync(folderPath)
  }
}

module.exports = (args) => ({
  mode: 'production',
  entry: ['./src/index.ts'],
  target: 'node',
  output: {
    library: 'waves-items',
    libraryTarget: 'commonjs2',
    filename: 'index.js',
    path: path.resolve(__dirname, 'dist')
  },
  optimization: {
    minimize: false,

  },
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/
      }
    ]
  },
  resolve: {
    extensions: ['.ts', '.js']
  },
  plugins: [
    new copy([
      { from: 'README.md' }
    ]),
    {
      apply: (compiler) =>
        compiler.plugin('done', function () {
          deleteFolder('dist/libs')
        })
    }
  ]
})