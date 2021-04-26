import { nodeResolve } from '@rollup/plugin-node-resolve';
import typescript from 'rollup-plugin-typescript2';

export default {
  input: 'src/index.ts',
  output: {
    dir: 'dist',
    format: 'es',
  },
  external: [/^jose\//],
  plugins: [
    nodeResolve(),
    typescript({ tsconfigOverride: { compilerOptions: { module: 'ES2015' } } }),
  ],
};
