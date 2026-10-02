import { defineConfig, globalIgnores } from 'eslint/config'
import tseslint from 'typescript-eslint'

// Flat ESLint config for the Workers gateway: typescript-eslint's recommended
// rules — the same TypeScript rule set the Vue repos get via @vue/eslint-config-typescript,
// without that preset's Vue-only dependencies.
export default defineConfig(
  globalIgnores(['**/dist/**', '**/coverage/**', '**/*.d.ts']),
  {
    name: 'nft-gate-workers/typescript',
    files: ['**/*.{ts,mts,tsx}'],
    extends: [tseslint.configs.recommended],
  },

  {
    name: 'nft-gate-workers/overrides',
    files: ['**/*.{ts,mts,tsx}'],
    rules: {
      // Underscore-prefixed args/vars are an intentional "unused" marker; rest-sibling
      // destructuring (`const { a, ...rest } = x`) is a legitimate key-omission pattern.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', ignoreRestSiblings: true },
      ],
    },
  },
)
