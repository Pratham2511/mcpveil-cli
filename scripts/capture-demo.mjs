// Capture demo frames with playwright and stitch into a GIF with ffmpeg.
import pkg from "/home/z/.npm-global/lib/node_modules/playwright/index.js";
const { chromium } = pkg;
import { execSync } from "node:child_process";
import { readdirSync, rmSync } from "node:fs";

const FRAMES = "/tmp/demo-frames";
const OUT = "/home/z/my-project/mcpveil/assets/demo.gif";

rmSync(FRAMES, { recursive: true, force: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1000, height: 680 }, deviceScaleFactor: 1.5 });
await page.goto("file:///home/z/my-project/mcpveil/scripts/demo.html");
await page.waitForTimeout(300);

const total = await page.evaluate(() => window.totalFrames);
const holds = { 2: 4, 3: 4 }; // pause on the connecting/inventory lines
let i = 0;
for (let step = 1; step <= total; step++) {
  const done = await page.evaluate(() => window.nextFrame());
  const repeats = holds[step] ?? (done ? 1 : 1);
  for (let r = 0; r < repeats; r++) {
    const name = `${FRAMES}/f${String(i).padStart(3, "0")}.png`;
    await page.screenshot({ path: name, clip: { x: 20, y: 20, width: 960, height: 640 } });
    i++;
  }
  await page.waitForTimeout(10);
}
await browser.close();

// hold the finished screen ~1.8s at 10fps
for (let h = 0; h < 18; h++) {
  execSync(`cp ${FRAMES}/f${String(i - 1).padStart(3, "0")}.png ${FRAMES}/f${String(i).padStart(3, "0")}.png`);
  i++;
}

const count = readdirSync(FRAMES).length;
console.log(`frames captured: ${count}`);

// two-pass palette GIF, 10fps, infinite loop
execSync(`ffmpeg -y -framerate 10 -i ${FRAMES}/f%03d.png -vf "palettegen=max_colors=64" /tmp/pal.png`, { stdio: "pipe" });
execSync(`ffmpeg -y -framerate 10 -i ${FRAMES}/f%03d.png -i /tmp/pal.png -lavfi "paletteuse=dither=bayer:bayer_scale=4" -loop 0 ${OUT}`, { stdio: "pipe" });
console.log("GIF written:", OUT);
