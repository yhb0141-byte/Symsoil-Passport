import { readFileSync } from 'node:fs';
import { verifyExport } from '../src/export-verifier.mjs';
if (!process.argv[2]) { console.error('用法：npm run verify-export -- 导出的记录.json'); process.exit(1); }
try { console.log(JSON.stringify(verifyExport(JSON.parse(readFileSync(process.argv[2], 'utf8'))), null, 2)); }
catch (error) { console.error(error.code || 'INVALID_EXPORT', error.message); process.exit(1); }
