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
  entry: {
    index: './src/index.ts',
    validation: './src/validation.ts',
  },
  target: 'node',
  output: {
    library: 'waves-crypto',
    libraryTarget: 'commonjs2',
    filename: '[name].js',
    path: path.resolve(__dirname, 'dist')
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
  optimization: {
    splitChunks: {
      chunks: "all",
      minSize: 0
    }
  },
  plugins: [
    new copy([{ from: 'README.md' }]),
    {
      apply: (compiler) =>
        compiler.plugin('done', function () {
          deleteFolder('dist/libs')
        })
    }
  ]
})