'use strict';

// puppeteer's browser download is the only caller, and the image uses
// Debian's Chromium instead (PUPPETEER_SKIP_DOWNLOAD=1).
module.exports = async function extractZip() {
  throw new Error('extract-zip is stubbed out in this image: browser downloads are not supported');
};
