// eslint.config.cjs
const tsParser = require('@typescript-eslint/parser');

module.exports = [
    {
        files: ['*.ts', '*.tsx', '*.js', '*.jsx'],
        languageOptions: {
            parser: tsParser,
            parserOptions: {
                ecmaVersion: 2025,
                sourceType: 'module'
            }
        },
        rules: {
            // semicolon: never
            'semi': ['error', 'never'],

            // arrow-return-shorthand: multiline
            'arrow-body-style': ['error', 'as-needed'],

            // trailing-comma
            'comma-dangle': ['error', {
                arrays: 'always-multiline',
                objects: 'always-multiline',
                functions: 'never',
                imports: 'always-multiline',
                exports: 'always-multiline'
            }],

            // indent: 2 spaces
            'indent': ['error', 2, { SwitchCase: 1 }],

            // whitespace
            'space-infix-ops': 'error',
            'space-before-blocks': 'error',
            'space-before-function-paren': ['error', 'never'],
            'space-in-parens': ['error', 'never'],
            'space-unary-ops': ['error', { words: true, nonwords: false }],
            'keyword-spacing': ['error', { before: true, after: true }],
            'semi-spacing': 'error',
            'comma-spacing': ['error', { before: false, after: true }],

            // quotes
            'quotes': ['error', 'single', { avoidEscape: true, allowTemplateLiterals: true }]
        }
    }
];
