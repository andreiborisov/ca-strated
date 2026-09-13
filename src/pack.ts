import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { copyFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';

import type { Paths } from './config.js';
import { INSTALL_ZIP_FILENAME } from './config.js';
import { CaStratedError } from './error.js';

const execFileAsync = promisify(execFile);

const INSTALL_READMES = ['README.md', 'README.ru.md'] as const;

export async function packInstallBundle(paths: Paths): Promise<void> {
  const installDir = join(paths.projectRoot, 'install');
  for (const name of INSTALL_READMES) {
    await copyFile(join(installDir, name), join(paths.outDir, name));
  }

  if (existsSync(paths.installZip)) {
    await unlink(paths.installZip);
  }

  try {
    await execFileAsync(
      'zip',
      ['-r', '-X', INSTALL_ZIP_FILENAME, 'trusted', 'untrusted', ...INSTALL_READMES, '-x', '*.DS_Store'],
      { cwd: paths.outDir },
    );
  } catch (error) {
    const err = error as { stderr?: string; message?: string };
    throw new CaStratedError(
      `Failed to write ${paths.installZip}: ${err.stderr?.trim() || err.message || String(error)}`,
    );
  }

  console.log(`wrote ${paths.installZip}`);
}
