import js from '@eslint/js';
import globals from 'globals';

export default [
  { ignores: ['build/', 'prebuilds/', 'node_modules/'] },
  js.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: { sourceType: 'commonjs', ecmaVersion: 2022, globals: { ...globals.node } },
  },
  {
    files: ['**/*.mjs'],
    languageOptions: { sourceType: 'module', ecmaVersion: 2022, globals: { ...globals.node } },
  },
];
