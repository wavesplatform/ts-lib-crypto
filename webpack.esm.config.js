const path = require('path')

module.exports = {
  mode: 'production',
  target: ['web', 'es2020'],
  entry: './src/index.ts',
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: {
          loader: 'ts-loader',
          options: {
            compilerOptions: {
              module: 'esnext',
              moduleResolution: 'bundler',
            },
          },
        },
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js'],
  },
  experiments: {
    outputModule: true,
  },
  output: {
    path: path.resolve(__dirname, 'dist/esm'),
    filename: 'index.mjs',
    module: true,
    library: {
      type: 'module',
    },
  },
}
