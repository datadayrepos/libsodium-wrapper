// @ts-check
import datadayrepos from '@antfu/eslint-config'
import sortKeys from 'eslint-plugin-sort-keys'

export default datadayrepos(
  {
    typescript: true,
    stylistic: {
      indent: 2, // 4, or 'tab'
      quotes: 'single', // or 'double'
    },
    overrides: {
      typescript: {
        'ts/consistent-type-definitions': ['error', 'type'],
      },
      yaml: {},
      // ...
    },
  },
  {
    ignores: [
      // eslint ignore globs paths here
      'dist',
      'dist-test',
    ],
  },
  {
    files: ['src/**/*.ts'],
    plugins: {
      'sort-keys': sortKeys,
    },
    rules: {
      'sort-keys/sort-keys-fix': 'error',
    },
  },
  {
    rules: {
      // overrides
      'node/prefer-global/process': 'off',
    },
  },
  {
    files: ['src/**/*.ts'],
    rules: {},
  },
)
