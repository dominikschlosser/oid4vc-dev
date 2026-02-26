// @ts-check
const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: ".",
  testMatch: "*.spec.js",
  timeout: 30_000,
  retries: 0,
  use: {
    baseURL: "http://localhost:18923",
    headless: true,
  },
  webServer: {
    command: "go build -o /tmp/ssi-debugger-e2e .. && /tmp/ssi-debugger-e2e serve --port 18923",
    url: "http://localhost:18923",
    reuseExistingServer: true,
    timeout: 15_000,
  },
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
  ],
});
