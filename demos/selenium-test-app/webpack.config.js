const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const webpack = require('webpack');

module.exports = {
  entry: {
    bundle: path.join(__dirname, 'src/main.js'),
  },
  mode: 'production',
  target: 'web',
  output: {
    path: path.join(__dirname, 'dist'),
  },
  resolve: {
    alias: {
      process: "process/browser"
    },
    fallback: {
      "assert": require.resolve("assert/"),
      "buffer": require.resolve("buffer/"),
      "events": require.resolve("events/"),
      "stream": require.resolve("stream-browserify/"),
      "util": require.resolve("util/"),
    },
  },
  devtool: 'source-map',
  devServer: {
    client: {
      overlay: false
    }
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: 'src/index.html',
      filename: 'index.html',
    }),
    new webpack.ProvidePlugin({
      Buffer: [require.resolve('buffer/'), 'Buffer'],
      process: require.resolve('process/browser'),
    }),
  ],
};
