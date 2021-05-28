import { defineConfig } from 'vite'
import alias from '@rollup/plugin-alias'
import vue from '@vitejs/plugin-vue'

let path = require('path')
// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    vue(),
    alias({
      entries: [
        { find: 'src', replacement: path.resolve(__dirname, 'src') }
      ]
    }),
  ]
})
