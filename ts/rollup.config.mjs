import { dts } from "rollup-plugin-dts";

export default [
  {
    input: 'build/hippo.js',
    output: {
      file: 'hippo.bundle.js'
    }
  },
  {
    input: 'build/hippo.d.ts',
    output: {
      file: 'hippo.bundle.d.ts'
    },
    plugins: [dts()],
  }
]
