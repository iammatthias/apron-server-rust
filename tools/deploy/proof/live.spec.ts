import { execFileSync } from 'node:child_process';
import { expect, test, type Page } from '@playwright/test';

const handle = process.env.APRON_PROOF_HANDLE ?? 'ladle-proof';
const ladleDir = process.env.LADLE_DIR!;

const composer = (page: Page) => page.getByRole('textbox', { name: 'Message', exact: true });
const profileButton = (page: Page) => page.getByRole('button', { name: /^Your profile on/ });
const profileDialog = (page: Page) => page.getByRole('dialog', { name: 'Edit profile' });
const connectCard = (page: Page) => page.getByRole('form', { name: 'Sign in' });
const messageByText = (page: Page, text: string) => page.locator('article[data-message-id]').filter({ hasText: text }).first();

async function send(page: Page, text: string): Promise<void> {
	await composer(page).fill(text);
	const button = text.startsWith('/') ? 'Run command' : 'Send message';
	await page.getByRole('button', { name: button, exact: true }).click();
}

/** The code blocks of the newest notice that says `phrase`, read in the page so no assertion prints them. */
async function noticeCodeBlocks(page: Page, phrase: string): Promise<string[]> {
	return page.evaluate((phrase) => {
		const hits = [...document.querySelectorAll('pre')].filter((pre) => {
			let node: Element | null = pre;
			while (node && !node.textContent?.includes(phrase)) node = node.parentElement;
			return node !== null;
		});
		let container: Element | null = hits.at(-1) ?? null;
		while (container && container.querySelectorAll('pre').length < 2) container = container.parentElement;
		return container ? [...container.querySelectorAll('pre')].slice(-2).map((pre) => (pre.querySelector('code') ?? pre).textContent!.trim()) : [];
	}, phrase);
}

test('a passkey account made in the web client signs Ladle in through /add-device', async ({ page, context, baseURL }) => {
	const cdp = await context.newCDPSession(page);
	await cdp.send('WebAuthn.enable');
	const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
		protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
		hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true
	} });

	await page.goto('/');
	await expect(page.getByTestId('connection-status')).toHaveText('Connected');
	await expect(composer(page)).toBeEnabled();

	await profileButton(page).click();
	await profileDialog(page).getByTestId('display-name-input').fill(handle);
	await profileDialog(page).getByRole('button', { name: 'Sign in with a passkey', exact: true }).click();
	await connectCard(page).getByRole('radiogroup', { name: 'Passkey', exact: true }).getByRole('radio', { name: /^Create account/ }).click();
	await expect(connectCard(page).getByTestId('connect-name-input')).toHaveValue(handle);
	await connectCard(page).getByRole('button', { name: 'Create account with passkey', exact: true }).click();
	await expect(connectCard(page)).toHaveCount(0);
	await expect(profileButton(page)).toContainText(handle);
	const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
	expect(credentials).toHaveLength(1);
	expect(credentials[0].rpId).toBe(new URL(baseURL!).hostname);

	if (!(await profileDialog(page).count())) await profileButton(page).click();
	const userID = (await profileDialog(page).locator('.ap-profedit-hint code').first().textContent())?.trim() ?? '';
	await profileDialog(page).getByRole('button', { name: 'Cancel', exact: true }).click();
	await expect(profileDialog(page)).toHaveCount(0);
	expect(userID).toMatch(/\S/);
	console.log(`web account: ${handle} (${userID})`);

	const webMessage = `web passkey proof ${Date.now()}`;
	await send(page, webMessage);
	await expect(messageByText(page, webMessage)).toBeVisible();

	await send(page, '/add-device phone');
	await expect(page.getByText(/^Sign in on “phone” as .* with this token/).last()).toBeVisible();
	const blocks = await noticeCodeBlocks(page, 'with this token');
	expect(blocks.length, 'the notice has a token block and an origin block').toBe(2);
	const [token, origin] = blocks;
	expect(/^\S{20,}$/.test(token), 'the first block is a token').toBe(true);
	expect(origin).toBe(new URL(baseURL!).origin);
	console.log(`/add-device notice: a token (${token.length} characters) for origin ${origin}`);

	const ladleMessage = `ladle session proof ${Date.now()}`;
	let output: string;
	try {
		output = execFileSync('swift', ['test', '--package-path', 'Packages/ApronKit', '--filter', 'LiveServerProofTests'], {
			cwd: ladleDir,
			encoding: 'utf8',
			stdio: ['ignore', 'pipe', 'pipe'],
			env: {
				...process.env,
				APRON_LIVE_URL: `${origin.replace(/^http/, 'ws')}/ws`,
				APRON_LIVE_ORIGIN: origin,
				APRON_LIVE_TOKEN: token,
				APRON_LIVE_USER_ID: userID,
				APRON_LIVE_MESSAGE: ladleMessage
			}
		});
	} catch (error: any) {
		output = `${error.stdout ?? ''}${error.stderr ?? ''}`;
		console.log(output.replaceAll(token, '<token>'));
		throw new Error('the Ladle session tests failed (output above)');
	}
	const summary = output.replaceAll(token, '<token>').split('\n').filter((line) => /Test Case .*(passed|failed|skipped)|Executed/.test(line));
	console.log(summary.join('\n'));
	expect(output).toMatch(/Executed 2 tests, with 0 failures/);
	expect(output).not.toMatch(/skipped/);

	const fromLadle = messageByText(page, ladleMessage);
	await expect(fromLadle).toBeVisible();
	console.log(`the page shows Ladle's message: ${await fromLadle.getAttribute('data-message-id')}`);
});
