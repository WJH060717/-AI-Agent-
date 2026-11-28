import { expect, test } from '@playwright/test';

const base = process.env.WORKSPACE_LAYOUT_E2E_URL;
test.skip(!base, 'WORKSPACE_LAYOUT_E2E_URL is required');

for (const width of [1366, 390]) {
  test(`workspace navigation and controls fit at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 768 });
    await page.route('**/api/v1/health/live', route => route.fulfill({ json: { status: 'ok' } }));
    await page.goto(base!);

    const nav = page.getByRole('banner').getByRole('navigation', { name: '操作步骤' });
    await expect(nav.getByRole('button', { name: '导入数据' })).toHaveAttribute('aria-current', 'step');
    await expect(page.getByLabel('访问令牌')).toBeVisible();
    await nav.getByRole('button', { name: '查看异常' }).click();
    await expect(page.getByRole('heading', { name: '查看异常', exact: true })).toBeFocused();
    await page.getByRole('button', { name: '去连接' }).click();
    await expect(page.getByLabel('访问令牌')).toBeVisible();
    await nav.getByRole('button', { name: '阅读报告' }).click();
    await expect(page.getByRole('heading', { name: '阅读报告', exact: true })).toBeFocused();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(width);
  });
}

test('workspace animates entry and lets the user reduce motion', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.goto(base!);
  const ambient = page.locator('.workspace-ambient');
  await expect.poll(() => ambient.evaluate(el => getComputedStyle(el, '::before').animationName)).toBe('ambient-drift');

  const nav = page.getByRole('navigation', { name: '操作步骤' });
  await nav.getByRole('button', { name: '查看异常' }).click();
  const empty = page.locator('.empty-state:visible');
  await expect(empty).toHaveCSS('animation-name', 'surface-enter');
  await expect(page.getByRole('heading', { name: '查看异常', exact: true })).toBeFocused();

  const toggle = page.getByRole('button', { name: '减少动效' });
  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-pressed', 'true');
  await expect(empty).toHaveCSS('animation-name', 'none');
  await expect.poll(() => ambient.evaluate(el => getComputedStyle(el, '::before').animationName)).toBe('none');
  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-pressed', 'false');
  await expect.poll(() => ambient.evaluate(el => getComputedStyle(el, '::before').animationName)).toBe('ambient-drift');
});

test('system reduced motion leaves content and navigation available without animation', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto(base!);
  await expect(page.getByLabel('访问令牌', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: '减少动效' })).toBeHidden();
  await expect(page.locator('.connect-panel')).toHaveCSS('animation-name', 'none');
  await page.getByRole('button', { name: '阅读报告', exact: true }).click();
  await expect(page.getByRole('heading', { name: '阅读报告', exact: true })).toBeFocused();
  await expect(page.getByRole('button', { name: '去连接' })).toBeVisible();
});
