import { nodeResolve } from '@rollup/plugin-node-resolve';
import typescript from 'rollup-plugin-typescript2';

export default {
  input: 'src/index.ts',
  output: {
    dir: 'dist',
    format: 'cjs',
  },
  external: [/^jose-node-cjs-runtime\//],
  plugins: [
    nodeResolve(),
    typescript({ tsconfigOverride: { compilerOptions: { module: 'ES2015' } } }),
  ],
};
