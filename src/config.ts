import { existsSync, readFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { z } from 'zod';

import { CaStratedError } from './error.js';

const sha256Schema = z
  .string()
  .regex(/^[0-9a-fA-F]{64}$/u, 'sha256 must be 64 hex characters')
  .transform((value) => value.toLowerCase());

const sourceSchema = z.object({
  url: z.string().url(),
  sha256: sha256Schema,
  subjectContains: z.string().min(1),
});

export const configSchema = z.object({
  sources: z.object({
    root: sourceSchema,
    intermediates: z.array(sourceSchema).min(1),
  }),
  permittedDns: z.array(z.string().min(1)).min(1),
  localCa: z.object({
    subject: z
      .string()
      .min(1)
      .refine((value) => value.startsWith('/'), 'OpenSSL subject must start with /'),
  }),
});

export type CertSource = z.infer<typeof sourceSchema>;
export type Config = z.infer<typeof configSchema>;

export const ANCHOR_CERT_FILENAME = 'castrated_constrained_anchor.crt';
export const ANCHOR_KEY_FILENAME = 'castrated_constrained_anchor.key';
export const WRAP_CERT_FILENAME = 'russian_trusted_root_castrated_pem.crt';
export const LEGACY_ANCHOR_KEY_FILENAMES = [
  'castrated_russian_trusted_root.key',
  'local-root.key',
] as const;

export type Paths = {
  projectRoot: string;
  configPath: string;
  vendorDir: string;
  outDir: string;
  trustedDir: string;
  untrustedDir: string;
  vendorRootCert: string;
  vendorIntermediateCerts: string[];
  untrustedIntermediateCerts: string[];
  localKey: string;
  legacyLocalKeys: string[];
  localRootCert: string;
  constrainedCert: string;
  extensionsConf: string;
};

export const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export function defaultConfigPath(root = projectRoot): string {
  const configPath = join(root, 'config.json');
  if (!existsSync(configPath)) {
    throw new CaStratedError(`No config.json in ${root}`);
  }
  return configPath;
}

export function upstreamCertFilename(url: string): string {
  let pathname: string;
  try {
    pathname = new URL(url).pathname;
  } catch {
    throw new CaStratedError(`invalid source URL: ${url}`);
  }
  const name = pathname.split('/').filter(Boolean).at(-1);
  if (!name || !name.endsWith('.crt')) {
    throw new CaStratedError(`source URL must end with a .crt filename: ${url}`);
  }
  if (name !== basename(name) || name.includes('..')) {
    throw new CaStratedError(`refusing unsafe cert filename from ${url}`);
  }
  return name;
}

export function loadConfig(configPath: string): Config {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(configPath, 'utf8')) as unknown;
  } catch (error) {
    throw new CaStratedError(
      `Failed to read config ${configPath}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  const parsed = configSchema.safeParse(raw);
  if (!parsed.success) {
    throw new CaStratedError(`Invalid config ${configPath}:\n${parsed.error.message}`);
  }
  return parsed.data;
}

export function resolvePaths(options: {
  config: Config;
  configPath: string;
  vendorDir?: string;
  outDir?: string;
}): Paths {
  const root = projectRoot;
  const vendorDir = resolve(options.vendorDir ?? join(root, 'vendor'));
  const outDir = resolve(options.outDir ?? join(root, 'out'));
  const trustedDir = join(outDir, 'trusted');
  const untrustedDir = join(outDir, 'untrusted');

  const intermediateNames = options.config.sources.intermediates.map((source) =>
    upstreamCertFilename(source.url),
  );
  const seen = new Set<string>();
  for (const name of intermediateNames) {
    if (seen.has(name)) {
      throw new CaStratedError(`duplicate upstream intermediate filename: ${name}`);
    }
    if (name === WRAP_CERT_FILENAME || name === ANCHOR_CERT_FILENAME) {
      throw new CaStratedError(`upstream filename collides with an issued cert name: ${name}`);
    }
    seen.add(name);
  }

  return {
    projectRoot: root,
    configPath: resolve(options.configPath),
    vendorDir,
    outDir,
    trustedDir,
    untrustedDir,
    vendorRootCert: join(vendorDir, 'root.crt'),
    vendorIntermediateCerts: options.config.sources.intermediates.map((_, index) =>
      join(vendorDir, `intermediate-${index}.crt`),
    ),
    untrustedIntermediateCerts: intermediateNames.map((name) => join(untrustedDir, name)),
    localKey: join(outDir, ANCHOR_KEY_FILENAME),
    legacyLocalKeys: LEGACY_ANCHOR_KEY_FILENAMES.map((name) => join(outDir, name)),
    localRootCert: join(trustedDir, ANCHOR_CERT_FILENAME),
    constrainedCert: join(untrustedDir, WRAP_CERT_FILENAME),
    extensionsConf: join(outDir, 'extensions.cnf'),
  };
}
