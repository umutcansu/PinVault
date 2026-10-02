// Bir QR görüntüsünü macOS'un kendi okuyucusuyla (CoreImage CIDetector)
// okur: panelin gösterdiği QR'ın gerçekten kodun kendisini taşıdığını,
// telefonun kamerasının göreceği gibi bağımsız bir okuyucu doğrular.
// osascript'in JavaScript (JXA) köprüsüyle çalışır; Xcode gerekmez.
const fs = require('fs');
const path = require('path');
const env = require('./env');

const SCRIPT = `ObjC.import('CoreImage');
ObjC.import('Foundation');
function run(argv) {
  const image = $.CIImage.imageWithContentsOfURL($.NSURL.fileURLWithPath(argv[0]));
  if (!image || image.isNil()) return 'NO_IMAGE';
  const options = $.NSDictionary.dictionaryWithObjectForKey($.CIDetectorAccuracyHigh, $.CIDetectorAccuracy);
  const detector = $.CIDetector.detectorOfTypeContextOptions($.CIDetectorTypeQRCode, $(), options);
  const found = detector.featuresInImage(image);
  if (found.count === 0) return 'NO_QR';
  return ObjC.unwrap(found.objectAtIndex(0).messageString);
}
`;

/** Okuyucu betiğinin yolu: `osascript -l JavaScript <yol> <png>` QR'ın içeriğini yazar. */
function scriptPath() {
  fs.mkdirSync(env.LOCAL_DIR, { recursive: true });
  const file = path.join(env.LOCAL_DIR, 'qr-decode.js');
  fs.writeFileSync(file, SCRIPT);
  return file;
}

module.exports = { scriptPath };
