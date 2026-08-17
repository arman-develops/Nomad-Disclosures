import { readdirSync, statSync, writeFileSync } from 'fs';
import { join } from 'path';

const RESEARCH_DIR = 'Research';

function parseDDMMYYYY(dateStr) {
  const [day, month, year] = dateStr.split('-').map(Number);
  return new Date(year, month - 1, day);
}

function main() {
  const entries = readdirSync(RESEARCH_DIR, { withFileTypes: true })
    .filter(entry => entry.isDirectory())
    .map(entry => entry.name)
    // sanity check: only DD-MM-YYYY named folders
    .filter(name => /^\d{2}-\d{2}-\d{4}$/.test(name))
    .sort((a, b) => parseDDMMYYYY(b).getTime() - parseDDMMYYYY(a).getTime());

  const indexPath = join(RESEARCH_DIR, '.index.json');
  writeFileSync(indexPath, JSON.stringify(entries, null, 2) + '\n');

  console.log(`Wrote ${entries.length} entries to ${indexPath}`);
}

main();
