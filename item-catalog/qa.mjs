import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
import { loadOmowright } from 'file:///C:/Users/Administrator/.codex/plugins/cache/sisyphuslabs/omo/5.1.27/skills/browser/scripts/omowright.mjs';
const { omowright: o } = await loadOmowright();
const profile = mkdtempSync(join(tmpdir(), 'rich-catalog-qa-'));
const output = new URL('./test-artifacts/catalog/', import.meta.url);
mkdirSync(output, { recursive: true });
const data = JSON.parse(readFileSync(new URL('./public/catalog.json', import.meta.url)));
const keys = ['cards', 'events', 'roles', 'npcs', 'maps', 'mall', 'sounds', 'music'];
const browser = await o.connectPipe({ browserPath: 'C:/Program Files/Google/Chrome/Application/chrome.exe', browserArgs: ['--headless', '--mute-audio', '--no-first-run', `--user-data-dir=${profile}`], storageRoot: profile, dialogPolicy: { accept: true } });
const results = [];
try {
  const page = await browser.newTab('http://127.0.0.1:4173/');
  await page.goto('http://127.0.0.1:4173/');
  const viewport = async (width, height) => o.emulate(page, { width, height, deviceScaleFactor: 1, mobile: width < 768, hasTouch: width < 768 });
  await viewport(1440, 1000);
  async function capture(name) {
    await page.evaluate(async () => {
      await document.fonts.ready;
      const images = [...document.images];
      images.forEach(i => i.loading = 'eager');
      await Promise.all(images.map(i => i.decode().catch(() => {})));
    });
    writeFileSync(new URL(`${name}.png`, output), await page.screenshot());
  }
  for (const key of keys) {
    await page.locator(`#catalog-nav a[href="#${key}"]`).click();
    const state = await page.evaluate(() => ({
      rows: document.querySelectorAll('tbody tr').length,
      columns: document.querySelectorAll('th').length,
      active: document.querySelector('a[aria-current="page"]').hash,
      preload: [...document.querySelectorAll('audio')].every(a => a.preload === 'none' && a.readyState === 0),
      extra: document.querySelectorAll('header,footer,dialog,input').length,
      invalid: [...document.querySelectorAll('tbody td')].filter(n => /undefined|NaN|\[object Object\]/.test(n.textContent)).length,
    }));
    assert.equal(state.rows, Math.min(100, data[key].length));
    assert.equal(state.active, `#${key}`);
    assert.equal(state.extra, 0);
    assert.equal(state.invalid, 0);
    assert.equal(state.preload, true);
    if (key === 'cards') {
      assert.equal(await page.evaluate(() => document.querySelector('tr[data-id="1031"] .price-cell').textContent), '50 点券');
      assert.equal(await page.evaluate(() => document.querySelector('tr[data-id="500"] .price-cell').textContent), '不在商店出售');
    }
    if (key === 'mall') assert.equal(await page.evaluate(() => document.querySelector('tr[data-id="4"] .price-cell').textContent), '1 代币');
    await capture(`${key}-desktop`);
    if (data[key].length > 100) {
      const seen = await page.evaluate(() => [...document.querySelectorAll('tbody tr')].map(n => n.dataset.id));
      for (let i = 1; i < Math.ceil(data[key].length / 100); i++) {
        await page.locator('#next-page').click();
        seen.push(...await page.evaluate(() => [...document.querySelectorAll('tbody tr')].map(n => n.dataset.id)));
      }
      assert.equal(seen.length, data[key].length);
      assert.equal(new Set(seen).size, seen.length);
      assert.deepEqual(seen, data[key].map(n => String(n.id)));
      assert.equal(await page.evaluate(() => document.querySelector('#next-page').disabled), true);
      await capture(`${key}-last`);
      await page.locator('#page-number').selectOption('0');
    }
    await viewport(390, 844);
    await page.evaluate(() => { scrollTo(0,0); document.querySelector('.table-container').scrollLeft = 0; });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await capture(`${key}-mobile`);
    await page.evaluate(() => document.querySelector('.table-container').scrollLeft = 9999);
    await capture(`${key}-mobile-right`);
    await page.evaluate(() => document.querySelector('.table-container').scrollLeft = 0);
    await viewport(1440, 1000);
    results.push({ page: key, entries: data[key].length, ...state });
  }
  // Confirm actual browser decoding for every audio file, in bounded batches.
  const audioUrls = [...data.sounds, ...data.music].map(r => r.audio);
  for (let i = 0; i < audioUrls.length; i += 32) {
    const failed = await page.evaluate(async (urls) => {
      return (await Promise.all(urls.map(url => new Promise(resolve => {
        const audio = new Audio(); audio.muted = true;
        const timer = setTimeout(() => finish(false), 12000);
        function finish(ok) { clearTimeout(timer); audio.onloadedmetadata = null; audio.onerror = null; audio.removeAttribute('src'); audio.load(); resolve(ok ? null : url); }
        audio.onloadedmetadata = () => finish(Number.isFinite(audio.duration) && audio.duration > 0);
        audio.onerror = () => finish(false);
        audio.src = url; audio.preload = 'metadata';
      })))).filter(Boolean);
    }, audioUrls.slice(i, i + 32));
    assert.deepEqual(failed, [], 'audio files decode');
  }
  await page.locator('#catalog-nav a[href="#music"]').click();
  const playback = await page.evaluate(async () => {
    const [first, second] = document.querySelectorAll('audio');
    first.muted = true; second.muted = true;
    await first.play();
    const started = !first.paused;
    await second.play();
    return { started, single: first.paused && !second.paused };
  });
  assert.deepEqual(playback, { started: true, single: true });
  await page.locator('#catalog-nav a[href="#cards"]').click();
  assert.equal(await page.evaluate(() => document.querySelectorAll('audio').length), 0);
  await page.goto('http://127.0.0.1:4173/#roles');
  assert.equal(await page.evaluate(() => document.querySelectorAll('tbody tr').length), 9);
  await page.goto(pathToFileURL(join(process.cwd(), 'item-catalog/public/index.html')).href + '#npcs');
  assert.equal(await page.evaluate(() => document.querySelectorAll('tbody tr').length), 34);
  writeFileSync(new URL('checks.json', output), JSON.stringify({ status: 'PASS', pages: results, audioDecoded: audioUrls.length, playback, offline: true, directRoute: true }, null, 2));
  console.log(JSON.stringify({ status: 'PASS', pages: results.map(r => [r.page, r.entries]), audioDecoded: audioUrls.length, playback, offline: true }));
} finally {
  await browser.close();
  rmSync(profile, { recursive: true, force: true });
}
