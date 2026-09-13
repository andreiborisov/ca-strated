import { relative } from 'node:path';

import { defaultConfigPath, loadConfig, projectRoot, resolvePaths, type Paths } from './config.js';
import { CaStratedError } from './error.js';
import { fetchCertificates } from './fetch.js';
import { inspectCertificates } from './inspect.js';
import { issueCertificates } from './issue.js';
import { opensslVersion } from './openssl.js';
import { prove } from './prove.js';

const COMMANDS = ['all', 'fetch', 'inspect', 'issue', 'prove'] as const;
type Command = (typeof COMMANDS)[number];

function usage(): string {
  return `Usage: pnpm ca-strated [fetch|inspect|issue|prove|all] [--config path] [--vendor dir] [--out dir]

  fetch    Download НУЦ PEMs and check file SHA-256 pins
  inspect  Check subjects, CA bits, expiry, and Sub CA signatures
  issue    Cross-sign, write trusted/untrusted, pack the install zip
  prove    Check copied dates, dump constraints, and run synthetic allow/deny leaves
  all      fetch → inspect → issue → prove (default)
`;
}

function isCommand(value: string): value is Command {
  return (COMMANDS as readonly string[]).includes(value);
}

function parseArgs(argv: string[]): {
  command: Command;
  configPath?: string;
  vendorDir?: string;
  outDir?: string;
} {
  let command: Command = 'all';
  let configPath: string | undefined;
  let vendorDir: string | undefined;
  let outDir: string | undefined;
  let seenCommand = false;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === undefined) {
      continue;
    }
    if (arg === '-h' || arg === '--help') {
      console.log(usage());
      process.exit(0);
    }
    if (arg === '--config' || arg === '--vendor' || arg === '--out') {
      const value = argv[i + 1];
      if (!value || value.startsWith('-')) {
        throw new CaStratedError(`${arg} requires a path`);
      }
      i += 1;
      if (arg === '--config') {
        configPath = value;
      } else if (arg === '--vendor') {
        vendorDir = value;
      } else {
        outDir = value;
      }
      continue;
    }
    if (arg.startsWith('-')) {
      throw new CaStratedError(`Unknown option ${arg}\n\n${usage()}`);
    }
    if (seenCommand) {
      throw new CaStratedError(`Unexpected argument ${arg}\n\n${usage()}`);
    }
    if (!isCommand(arg)) {
      throw new CaStratedError(`Unknown command ${arg}\n\n${usage()}`);
    }
    command = arg;
    seenCommand = true;
  }

  return { command, configPath, vendorDir, outDir };
}

async function run(command: Command, config: ReturnType<typeof loadConfig>, paths: Paths): Promise<void> {
  switch (command) {
    case 'fetch':
      await fetchCertificates(config, paths);
      break;
    case 'inspect':
      await inspectCertificates(config, paths);
      break;
    case 'issue':
      await issueCertificates(config, paths);
      break;
    case 'prove':
      await prove(config, paths);
      break;
    case 'all':
      await fetchCertificates(config, paths);
      await inspectCertificates(config, paths);
      await issueCertificates(config, paths);
      await prove(config, paths);
      break;
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const configPath = args.configPath ?? defaultConfigPath();
  const config = loadConfig(configPath);
  const paths = resolvePaths({
    config,
    configPath,
    vendorDir: args.vendorDir,
    outDir: args.outDir,
  });

  console.log(`openssl: ${await opensslVersion()}`);
  console.log(`config:  ${relative(projectRoot, paths.configPath) || paths.configPath}`);

  await run(args.command, config, paths);
}

try {
  await main();
} catch (error) {
  const message = error instanceof CaStratedError ? error.message : error instanceof Error ? error.stack : String(error);
  console.error(message);
  process.exit(1);
}
