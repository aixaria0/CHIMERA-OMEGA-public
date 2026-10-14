import fs from 'node:fs';
import { verifyClaimEnvelope } from './verify.mjs';

const path = process.argv[2];
if (!path) {
  console.error('usage: node src/cli.mjs <claim.json>');
  process.exit(2);
}

try {
  const envelope = JSON.parse(fs.readFileSync(path, 'utf8'));
  const report = verifyClaimEnvelope(envelope);
  console.log(JSON.stringify(report, null, 2));
  process.exit(report.status === 'FAIL' ? 1 : 3);
} catch {
  console.log(JSON.stringify({ status: 'FAIL', reasons: ['Unable to read a legacy JSON envelope.'] }));
  process.exit(2);
}
