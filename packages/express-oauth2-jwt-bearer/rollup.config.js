import { nodeResolve } from '@rollup/plugin-node-resolve';
import typescript from 'rollup-plugin-typescript2';
import dts from 'rollup-plugin-dts';

export default [
  {
    input: 'src/index.ts',
    output: {
      dir: 'dist',
      format: 'cjs',
    },
    external: ['jose'],
    plugins: [
      nodeResolve(),
      typescript({
        tsconfigOverride: { compilerOptions: { module: 'ES2015' } },
      }),
    ],
  },
  {
    input: 'src/index.ts',
    output: {
      dir: 'dist',
      format: 'es',
    },
    external: ['express', 'http', 'https'],
    plugins: [dts({ respectExternal: true })],
  },
];
