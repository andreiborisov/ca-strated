import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
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

export type Paths = {
  projectRoot: string;
  configPath: string;
  vendorDir: string;
  outDir: string;
  vendorRootCert: string;
  vendorIntermediateCerts: string[];
  localKey: string;
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
  return {
    projectRoot: root,
    configPath: resolve(options.configPath),
    vendorDir,
    outDir,
    vendorRootCert: join(vendorDir, 'root.crt'),
    vendorIntermediateCerts: options.config.sources.intermediates.map((_, index) =>
      join(vendorDir, `intermediate-${index}.crt`),
    ),
    localKey: join(outDir, 'local-root.key'),
    localRootCert: join(outDir, 'local-root.crt'),
    constrainedCert: join(outDir, 'mincifry-constrained.crt'),
    extensionsConf: join(outDir, 'extensions.cnf'),
  };
}
