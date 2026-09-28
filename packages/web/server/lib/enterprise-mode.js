import fs from 'node:fs';
import path from 'node:path';

import { z } from 'zod';

/**
 * Enterprise mode: an administrator's promise that conversation content goes
 * only to the model providers configured in OpenCode. Two sources turn it on,
 * and either one is enough:
 * - the machine policy file (`policyFilePaths`), which only an administrator
 *   can write and a device manager can roll out; nothing a user sets can
 *   turn off what it turns on;
 * - `OPENCHAMBER_ENTERPRISE_MODE=1` (or `true`) in the server's environment,
 *   which includes the login-shell snapshot. Meant for servers and containers,
 *   where the administrator owns the environment.
 * Read at every use, so a changed file applies without a restart.
 *
 * The policy file also pins the self-hosted relay and the Jev endpoint. A
 * value in the file wins over its environment variable; the variable applies
 * only when the file does not name that value. A file that exists but cannot
 * be read or parsed turns enterprise mode on and pins nothing: a broken
 * policy must not quietly lift the protection it was meant to give.
 *
 * Each feature that could send conversation content anywhere else checks it
 * at its own server boundary:
 * - Model providers come only from the OpenCode config: connecting one,
 *   signing in, adding a key or creating a custom provider through this
 *   server is refused (`opencode/routes.js`). OpenCode's `provider.use`
 *   policy is the real lock; this closes the way in through the app.
 * - Jev classification is off, unless the administrator pinned their own
 *   endpoint (`routing/runtime.js`).
 * - External tunnels are refused: their provider sees plain text (`tunnels`).
 * - The private relay runs only on a pinned self-hosted endpoint
 *   (`relay/service.js`).
 * - Speech and transcription go only to servers on this machine (`tts`,
 *   `dictation`).
 * - Push notifications carry no message text or session name (`notifications`).
 * - Update checks still run but never report usage (`package-manager.js`).
 * The VS Code extension host, which runs no OpenChamber server, reads the
 * same policy through this module for the parts it has (provider connection,
 * update checks).
 */

const WINDOWS_PROGRAM_DATA = 'C:\\ProgramData';

/**
 * Where the machine policy may live, most authoritative first. The paths are
 * fixed on purpose: a location a user could redirect (an environment variable,
 * a setting) would let them point it at an empty file. On Windows the
 * `ProgramData` variable is consulted only after the fixed location, so
 * redirecting it cannot hide a policy the administrator placed there.
 */
export const policyFilePaths = ({ platform = process.platform, env = process.env } = {}) => {
  if (platform === 'darwin') return ['/Library/Application Support/OpenChamber/policy.json'];
  if (platform === 'win32') {
    const fixed = path.win32.join(WINDOWS_PROGRAM_DATA, 'OpenChamber', 'policy.json');
    const programData = (env.ProgramData ?? '').trim();
    const fromEnv = programData ? path.win32.join(programData, 'OpenChamber', 'policy.json') : null;
    return fromEnv && fromEnv.toLowerCase() !== fixed.toLowerCase() ? [fixed, fromEnv] : [fixed];
  }
  return ['/etc/openchamber/policy.json'];
};

// A blank string counts as unset, so a template with empty fields pins nothing.
const optionalText = z.string().trim().transform((value) => value || undefined).optional();

const policyFileSchema = z.object({
  enterpriseMode: z.boolean().optional(),
  organization: optionalText,
  relayUrl: optionalText,
  jev: z.object({ url: optionalText, model: optionalText, apiKey: optionalText }).optional(),
}).refine((policy) => !policy.jev || policy.jev.url || (!policy.jev.model && !policy.jev.apiKey), {
  message: '"jev" needs a "url"',
  path: ['jev'],
});

/** The file's content; throws an Error saying what is wrong with it. */
const parsePolicyFile = (text) => {
  let raw;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    throw new Error(`not valid JSON (${error.message})`);
  }
  const parsed = policyFileSchema.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const field = issue.path.length > 0 ? `"${issue.path.join('.')}": ` : '';
    throw new Error(`${field}${issue.message}`);
  }
  const { enterpriseMode, organization, relayUrl, jev } = parsed.data;
  return {
    enterpriseMode: enterpriseMode === true,
    organization: organization ?? null,
    relayUrl,
    jev: jev?.url ? { url: jev.url, model: jev.model ?? null, apiKey: jev.apiKey ?? null } : undefined,
  };
};

const defaultReadFile = (filePath) => fs.readFileSync(filePath, 'utf8');

let lastWarning = null;
const warnOnce = (message) => {
  if (message === lastWarning) return;
  lastWarning = message;
  console.warn(`[enterprise] ${message}`);
};

/**
 * The machine policy file: `{ status: 'absent' }`, `{ status: 'ok', path,
 * policy }`, or `{ status: 'invalid', path, error }` when it exists but cannot
 * be used.
 */
const readPolicyFile = ({ platform = process.platform, env = process.env, readFile = defaultReadFile } = {}) => {
  for (const filePath of policyFilePaths({ platform, env })) {
    let text;
    try {
      text = readFile(filePath);
    } catch (error) {
      if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') continue;
      const message = `cannot read ${filePath}: ${error?.message || error}`;
      warnOnce(`${message}; enterprise mode stays on`);
      return { status: 'invalid', path: filePath, error: message };
    }
    try {
      return { status: 'ok', path: filePath, policy: parsePolicyFile(text) };
    } catch (error) {
      const message = `${filePath}: ${error.message}`;
      warnOnce(`${message}; enterprise mode stays on`);
      return { status: 'invalid', path: filePath, error: message };
    }
  }
  return { status: 'absent' };
};

const envFlag = (env) => {
  const value = (env.OPENCHAMBER_ENTERPRISE_MODE ?? '').trim().toLowerCase();
  return value === '1' || value === 'true';
};

const envString = (env, name) => (env[name] ?? '').trim() || null;

/**
 * The policy in effect, from the file and the environment together.
 * `relayUrl` and `jev` are the raw pinned values; their consumers validate
 * them and treat an invalid one as unset. `source` says where enterprise mode
 * came from, for the UI and the logs.
 */
export const readEnterprisePolicy = (options = {}) => {
  const env = options.env ?? process.env;
  const file = readPolicyFile(options);

  if (file.status === 'invalid') {
    return {
      enterpriseMode: true,
      source: 'policy-file',
      organization: null,
      policyError: file.error,
      relayUrl: null,
      jev: null,
    };
  }

  const fromFile = file.status === 'ok' ? file.policy : null;
  const envJevUrl = envString(env, 'OPENCHAMBER_JEV_URL');
  const jev = fromFile?.jev
    ?? (envJevUrl
      ? { url: envJevUrl, model: envString(env, 'OPENCHAMBER_JEV_MODEL'), apiKey: envString(env, 'OPENCHAMBER_JEV_API_KEY') }
      : null);
  const enterpriseMode = fromFile?.enterpriseMode === true || envFlag(env);

  return {
    enterpriseMode,
    source: fromFile?.enterpriseMode ? 'policy-file' : enterpriseMode ? 'environment' : null,
    organization: fromFile?.organization ?? null,
    policyError: null,
    relayUrl: fromFile?.relayUrl ?? envString(env, 'OPENCHAMBER_RELAY_URL'),
    jev,
  };
};

export const isEnterpriseMode = (options) => readEnterprisePolicy(options).enterpriseMode;

/** What a client may know about the policy; pinned endpoints and keys stay on the server. */
export const publicEnterprisePolicy = (options) => {
  const { enterpriseMode, source, organization, policyError } = readEnterprisePolicy(options);
  return { enterpriseMode, source, organization, policyError };
};

// OpenCode routes that connect a provider, sign in or add a key: every POST
// under `/api/integration/:id/connect` (key, oauth start and complete,
// command) and adding a well-known integration. Reads, cancelling an attempt
// and removing or switching an existing account stay allowed: they only
// narrow access.
const PROVIDER_CONNECT_PATH = /^\/api\/(?:integration\/[^/?]+\/connect(?:\/[^?]*)?|experimental\/integration\/wellknown)\/?(?:\?|$)/;

/** Whether a request to OpenCode would add a way to reach a model provider. */
export const isProviderConnectRequest = (method, requestPath) => (
  String(method).toUpperCase() === 'POST' && PROVIDER_CONNECT_PATH.test(requestPath)
);

export const ENTERPRISE_MODE_ERROR = 'Not available in enterprise mode: this server keeps conversations with the model providers configured in OpenCode.';
