import sharp from 'sharp';
import { fileURLToPath } from 'node:url';

const root = new URL('../', import.meta.url);
const path = (name) => fileURLToPath(new URL(name, root));
const layout = path('docs/assets/cleopatr-architecture-layout.png');
const output = path('docs/assets/cleopatr-architecture.png');

// Place the canonical PNG artwork directly. Only transparent outer padding is
// trimmed; visible artwork, aspect ratios, colors and alpha are preserved.
const placements = [
  { file: 'cleopatr-logo.png', left: 104, top: 16, width: 310, height: 242 },
  { file: 'cleopatr-feather.png', left: 52, top: 379, width: 33, height: 70 },
  { file: 'cleo-logo.png', left: 96, top: 381, width: 116, height: 44 },
  { file: 'cleopatr-feather.png', left: 923, top: 55, width: 13, height: 26 },
];
const overlays = await Promise.all(
  placements.map(async ({ file, left, top, width, height }) => ({
    input: await sharp(path(`public/brand/${file}`))
      .trim()
      .resize({ width, height, fit: 'inside' })
      .png()
      .toBuffer(),
    left,
    top,
  })),
);
await sharp(layout).composite(overlays).png().toFile(output);
console.log(`Updated ${output} using the original brand PNG assets.`);
