import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    testTimeout: 10000,
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
    },
  },
});
