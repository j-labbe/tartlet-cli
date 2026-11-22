import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["**/dist/**", "node_modules/**"] },
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,js,mjs}"],
    rules: {
      complexity: ["error", 10],
      "no-console": "error",
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-non-null-assertion": "error",
      "@typescript-eslint/consistent-type-assertions": ["error", { assertionStyle: "never" }],
      "@typescript-eslint/no-unused-vars": ["error", { varsIgnorePattern: "^_", argsIgnorePattern: "^_" }],
    },
  },
);
