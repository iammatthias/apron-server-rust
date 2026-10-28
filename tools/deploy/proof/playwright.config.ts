import { defineConfig, devices } from '@playwright/test';

const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;

// No traces, screenshots or videos: the page shows a live bearer token.
export default defineConfig({
	testDir: '.',
	testMatch: /live\.spec\.ts$/,
	workers: 1,
	retries: 0,
	timeout: 15 * 60_000,
	expect: { timeout: 20_000 },
	reporter: 'list',
	outputDir: './test-results',
	use: {
		...devices['Desktop Chrome'],
		actionTimeout: 20_000,
		baseURL: process.env.APRON_LIVE_BASE_URL ?? 'https://apron.farfield.systems',
		trace: 'off',
		screenshot: 'off',
		video: 'off',
		...(executablePath ? { launchOptions: { executablePath } } : {})
	}
});
