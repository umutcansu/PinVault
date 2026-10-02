// PinVault dashboard — QR code for enrollment codes.
//
// A small QR Code Model 2 encoder (ISO/IEC 18004): byte mode, error
// correction level M, versions 1–10 (up to 213 bytes), mask chosen by the
// standard penalty rules. Written after Project Nayuki's reference encoder
// (MIT). Kept in the dashboard so the panel loads nothing from elsewhere
// (CSP `script-src 'self'`). qrSvg() returns an inline <svg>.

const QR = (() => {
  // Error correction level M, indexed by version (0 unused).
  const ECC_PER_BLOCK = [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26];
  const NUM_BLOCKS = [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5];
  const MAX_VERSION = 10;
  const FORMAT_BITS_M = 0; // L=1, M=0, Q=3, H=2

  function gfMultiply(x, y) {
    let z = 0;
    for (let i = 7; i >= 0; i--) {
      z = (z << 1) ^ ((z >>> 7) * 0x11d);
      z ^= ((y >>> i) & 1) * x;
    }
    return z;
  }

  function rsDivisor(degree) {
    const result = new Array(degree).fill(0);
    result[degree - 1] = 1;
    let root = 1;
    for (let i = 0; i < degree; i++) {
      for (let j = 0; j < result.length; j++) {
        result[j] = gfMultiply(result[j], root);
        if (j + 1 < result.length) result[j] ^= result[j + 1];
      }
      root = gfMultiply(root, 0x02);
    }
    return result;
  }

  function rsRemainder(data, divisor) {
    const result = divisor.map(() => 0);
    for (const b of data) {
      const factor = b ^ result.shift();
      result.push(0);
      divisor.forEach((coef, i) => { result[i] ^= gfMultiply(coef, factor); });
    }
    return result;
  }

  function rawDataModules(ver) {
    let result = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
      const numAlign = Math.floor(ver / 7) + 2;
      result -= (25 * numAlign - 10) * numAlign - 55;
      if (ver >= 7) result -= 36;
    }
    return result;
  }

  function dataCodewords(ver) {
    return Math.floor(rawDataModules(ver) / 8) - ECC_PER_BLOCK[ver] * NUM_BLOCKS[ver];
  }

  function alignmentPositions(ver, size) {
    if (ver === 1) return [];
    const numAlign = Math.floor(ver / 7) + 2;
    const step = Math.ceil((ver * 4 + 4) / (numAlign * 2 - 2)) * 2;
    const result = [6];
    for (let pos = size - 7; result.length < numAlign; pos -= step) result.splice(1, 0, pos);
    return result;
  }

  function utf8(text) {
    return Array.from(new TextEncoder().encode(text));
  }

  /** Data codewords: byte mode segment, terminator, padding. */
  function encodeData(bytes, ver) {
    const bits = [];
    const append = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
    append(0b0100, 4);
    append(bytes.length, ver <= 9 ? 8 : 16);
    bytes.forEach(b => append(b, 8));
    const capacity = dataCodewords(ver) * 8;
    append(0, Math.min(4, capacity - bits.length));
    append(0, (8 - bits.length % 8) % 8);
    for (let pad = 0xec; bits.length < capacity; pad ^= 0xec ^ 0x11) append(pad, 8);
    const out = [];
    for (let i = 0; i < bits.length; i += 8) {
      let b = 0;
      for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
      out.push(b);
    }
    return out;
  }

  function addEccAndInterleave(data, ver) {
    const numBlocks = NUM_BLOCKS[ver];
    const blockEccLen = ECC_PER_BLOCK[ver];
    const rawCodewords = Math.floor(rawDataModules(ver) / 8);
    const numShortBlocks = numBlocks - rawCodewords % numBlocks;
    const shortBlockLen = Math.floor(rawCodewords / numBlocks);
    const divisor = rsDivisor(blockEccLen);
    const blocks = [];
    for (let i = 0, k = 0; i < numBlocks; i++) {
      const dat = data.slice(k, k + shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1));
      k += dat.length;
      const ecc = rsRemainder(dat, divisor);
      if (i < numShortBlocks) dat.push(0);
      blocks.push(dat.concat(ecc));
    }
    const result = [];
    for (let i = 0; i < blocks[0].length; i++) {
      blocks.forEach((block, j) => {
        if (i !== shortBlockLen - blockEccLen || j >= numShortBlocks) result.push(block[i]);
      });
    }
    return result;
  }

  function encode(text) {
    const bytes = utf8(text);
    let ver = 1;
    while (ver <= MAX_VERSION && 4 + (ver <= 9 ? 8 : 16) + bytes.length * 8 > dataCodewords(ver) * 8) ver++;
    if (ver > MAX_VERSION) throw new Error('Text too long for a QR code here');

    const size = ver * 4 + 17;
    const modules = Array.from({ length: size }, () => new Array(size).fill(false));
    const isFunction = Array.from({ length: size }, () => new Array(size).fill(false));
    const setFunction = (x, y, dark) => { modules[y][x] = dark; isFunction[y][x] = true; };

    // Function patterns: timing, finders (with separators), alignment, format/version areas.
    for (let i = 0; i < size; i++) { setFunction(6, i, i % 2 === 0); setFunction(i, 6, i % 2 === 0); }
    for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
      for (let dy = -4; dy <= 4; dy++) {
        for (let dx = -4; dx <= 4; dx++) {
          const dist = Math.max(Math.abs(dx), Math.abs(dy));
          const x = cx + dx, y = cy + dy;
          if (x >= 0 && x < size && y >= 0 && y < size) setFunction(x, y, dist !== 2 && dist !== 4);
        }
      }
    }
    const align = alignmentPositions(ver, size);
    const n = align.length;
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        if ((i === 0 && j === 0) || (i === 0 && j === n - 1) || (i === n - 1 && j === 0)) continue;
        for (let dy = -2; dy <= 2; dy++) {
          for (let dx = -2; dx <= 2; dx++) setFunction(align[i] + dx, align[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        }
      }
    }
    const drawFormat = (mask) => {
      const data = (FORMAT_BITS_M << 3) | mask;
      let rem = data;
      for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
      const bits = ((data << 10) | rem) ^ 0x5412;
      const bit = (i) => ((bits >>> i) & 1) !== 0;
      for (let i = 0; i <= 5; i++) setFunction(8, i, bit(i));
      setFunction(8, 7, bit(6));
      setFunction(8, 8, bit(7));
      setFunction(7, 8, bit(8));
      for (let i = 9; i < 15; i++) setFunction(14 - i, 8, bit(i));
      for (let i = 0; i < 8; i++) setFunction(size - 1 - i, 8, bit(i));
      for (let i = 8; i < 15; i++) setFunction(8, size - 15 + i, bit(i));
      setFunction(8, size - 8, true);
    };
    drawFormat(0);
    if (ver >= 7) {
      let rem = ver;
      for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
      const bits = (ver << 12) | rem;
      for (let i = 0; i < 18; i++) {
        const dark = ((bits >>> i) & 1) !== 0;
        const a = size - 11 + i % 3, b = Math.floor(i / 3);
        setFunction(a, b, dark);
        setFunction(b, a, dark);
      }
    }

    // Data, in the zigzag order of the standard.
    const codewords = addEccAndInterleave(encodeData(bytes, ver), ver);
    let bitIndex = 0;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < size; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? size - 1 - vert : vert;
          if (!isFunction[y][x] && bitIndex < codewords.length * 8) {
            modules[y][x] = ((codewords[bitIndex >>> 3] >>> (7 - (bitIndex & 7))) & 1) !== 0;
            bitIndex++;
          }
        }
      }
    }

    const maskHit = (mask, x, y) => {
      switch (mask) {
        case 0: return (x + y) % 2 === 0;
        case 1: return y % 2 === 0;
        case 2: return x % 3 === 0;
        case 3: return (x + y) % 3 === 0;
        case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
        case 5: return (x * y) % 2 + (x * y) % 3 === 0;
        case 6: return ((x * y) % 2 + (x * y) % 3) % 2 === 0;
        default: return ((x + y) % 2 + (x * y) % 3) % 2 === 0;
      }
    };
    const applyMask = (mask) => {
      for (let y = 0; y < size; y++) {
        for (let x = 0; x < size; x++) if (!isFunction[y][x] && maskHit(mask, x, y)) modules[y][x] = !modules[y][x];
      }
    };

    // Standard penalty: runs, 2x2 blocks, finder-like patterns, balance.
    const penalty = () => {
      let result = 0;
      const addHistory = (run, history) => {
        if (history[0] === 0) run += size;
        history.pop();
        history.unshift(run);
      };
      const countPatterns = (h) => {
        const k = h[1];
        const core = k > 0 && h[2] === k && h[3] === k * 3 && h[4] === k && h[5] === k;
        return (core && h[0] >= k * 4 && h[6] >= k ? 1 : 0) + (core && h[6] >= k * 4 && h[0] >= k ? 1 : 0);
      };
      const terminate = (color, run, history) => {
        if (color) { addHistory(run, history); run = 0; }
        run += size;
        addHistory(run, history);
        return countPatterns(history);
      };
      for (const horizontal of [true, false]) {
        for (let a = 0; a < size; a++) {
          let color = false, run = 0;
          const history = [0, 0, 0, 0, 0, 0, 0];
          for (let b = 0; b < size; b++) {
            const m = horizontal ? modules[a][b] : modules[b][a];
            if (m === color) {
              run++;
              if (run === 5) result += 3;
              else if (run > 5) result++;
            } else {
              addHistory(run, history);
              if (!color) result += countPatterns(history) * 40;
              color = m;
              run = 1;
            }
          }
          result += terminate(color, run, history) * 40;
        }
      }
      for (let y = 0; y < size - 1; y++) {
        for (let x = 0; x < size - 1; x++) {
          const c = modules[y][x];
          if (c === modules[y][x + 1] && c === modules[y + 1][x] && c === modules[y + 1][x + 1]) result += 3;
        }
      }
      let dark = 0;
      modules.forEach(row => row.forEach(m => { if (m) dark++; }));
      const total = size * size;
      result += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10;
      return result;
    };

    let best = 0, bestScore = Infinity;
    for (let mask = 0; mask < 8; mask++) {
      applyMask(mask);
      drawFormat(mask);
      const score = penalty();
      if (score < bestScore) { best = mask; bestScore = score; }
      applyMask(mask); // XOR again: undo
    }
    applyMask(best);
    drawFormat(best);
    return { size, modules, version: ver, mask: best };
  }

  /** An inline SVG of [text] as a QR code, quiet zone included. */
  function svg(text, pixels = 200) {
    const { size, modules } = encode(text);
    const border = 4;
    const dim = size + border * 2;
    let path = '';
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) if (modules[y][x]) path += `M${x + border},${y + border}h1v1h-1z`;
    }
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" width="${pixels}" height="${pixels}" shape-rendering="crispEdges" role="img">` +
      `<rect width="${dim}" height="${dim}" fill="#ffffff"/><path d="${path}" fill="#000000"/></svg>`;
  }

  return { encode, svg };
})();

function qrSvg(text, pixels) { return QR.svg(text, pixels); }

if (typeof module !== 'undefined') module.exports = { QR };
