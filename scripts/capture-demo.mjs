// Optional demo tooling: install Playwright and FFmpeg before running.
import { chromium } from "playwright";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const frames = mkdtempSync(join(tmpdir(), "mcpveil-demo-"));
const output = fileURLToPath(new URL("../assets/demo.gif", import.meta.url));
const frame = (index) => join(frames, `f${String(index).padStart(3, "0")}.png`);
let browser;

try {
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1000, height: 680 }, deviceScaleFactor: 1.5 });
  await page.goto(new URL("./demo.html", import.meta.url).href);
  await page.waitForTimeout(300);

  const total = await page.evaluate(() => window.totalFrames);
  const holds = { 2: 4, 3: 4 };
  let count = 0;
  for (let step = 1; step <= total; step++) {
    await page.evaluate(() => window.nextFrame());
    for (let repeat = 0; repeat < (holds[step] ?? 1); repeat++) {
      await page.screenshot({ path: frame(count++), clip: { x: 20, y: 20, width: 960, height: 640 } });
    }
    await page.waitForTimeout(10);
  }
  const lastFrame = frame(count - 1);
  for (let hold = 0; hold < 18; hold++) copyFileSync(lastFrame, frame(count++));

  const palette = join(frames, "palette.png");
  execFileSync("ffmpeg", ["-y", "-framerate", "10", "-i", join(frames, "f%03d.png"),
    "-vf", "palettegen=max_colors=64", palette], { stdio: "pipe" });
  execFileSync("ffmpeg", ["-y", "-framerate", "10", "-i", join(frames, "f%03d.png"),
    "-i", palette, "-lavfi", "paletteuse=dither=bayer:bayer_scale=4", "-loop", "0", output], { stdio: "pipe" });
  console.log(`Captured ${count} frames into ${output}`);
} finally {
  await browser?.close();
  rmSync(frames, { recursive: true, force: true });
}
