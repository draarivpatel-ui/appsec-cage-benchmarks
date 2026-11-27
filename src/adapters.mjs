import { createHmac, createPrivateKey, createPublicKey, sign as ed25519Sign } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { scan } from 'sentinel-lint';
import { resolveSafePath } from 'pathcage';
import { assertSafeHeaderValue } from 'headersafe';
import { createRedirectGuard } from 'redirectcage';
import { defineEnv, t } from 'envcage';
import { parseCookieHeader } from 'cookiecage';
import { createZipBuffer, inspectZipBuffer } from 'zipcage';
import { sanitizeLogLine } from 'logcage';
import { createCorsPolicy } from 'corscage';
import { createJsonCage } from 'jsoncage';
import { signJwt, verifyJwt } from '@aarivbuildz/jwtguard';
import { createShield } from '@aarivbuildz/csrfshield';
import { verify as verifyWebhook, MemoryReplayStore } from '@aarivbuildz/hookverify';
import { validateUrl, validateRedirectChain } from '@aarivbuildz/urlguard';
import { analyzeRegex } from '@aarivbuildz/regex-shield';
import { inspectCsv } from '@aarivbuildz/csvshield';
import { createSanitizer } from '@aarivbuildz/htmlclean';
import { scanText } from '@aarivbuildz/secretsweep';

function packageRejection(error, prefix) {
  return error && typeof error.code === 'string' && error.code.startsWith(prefix);
}

function blockedFromThrown(error, prefix) {
  if (packageRejection(error, prefix)) {
    return { blocked: true, signal: error.code };
  }
  throw error;
}

function accepted(signal = 'accepted') {
  return { blocked: false, signal };
}

function expandZipValue(value) {
  if (value && typeof value === 'object' && !Array.isArray(value) && typeof value.repeat === 'string') {
    return value.repeat.repeat(value.count);
  }
  return value;
}

function prepareZipInput(input) {
  return {
    entries: input.entries.map((entry) => ({
      ...entry,
      data: expandZipValue(entry.data)
    }))
  };
}

function createSentinelAdapter() {
  return {
    async: true,
    async prepare(input, entry, context) {
      if (!input || typeof input !== 'object' || typeof input.filename !== 'string' || typeof input.content !== 'string') {
        throw new Error('sentinel-lint corpus inputs need filename and content strings');
      }
      const caseDir = path.join(context.workDir, 'sentinel-fixtures', entry.id);
      const fixturePath = path.join(caseDir, ...input.filename.split('/'));
      await mkdir(path.dirname(fixturePath), { recursive: true });
      await writeFile(fixturePath, input.content, 'utf8');
      await writeFile(path.join(caseDir, 'SECURITY.md'), '# Security\n\nReport vulnerabilities through the project security policy.\n', 'utf8');
      return { caseDir };
    },
    async invoke(benchCase) {
      const result = await scan({ root: benchCase.prepared.caseDir });
      const first = result.findings[0];
      return {
        blocked: result.findings.length > 0,
        signal: first ? first.ruleId : 'no-findings',
        findingCount: result.findings.length
      };
    }
  };
}

function createPathAdapter(context) {
  const root = path.join(context.workDir, 'contained-root');
  return {
    async: false,
    invoke(benchCase) {
      try {
        resolveSafePath(benchCase.input, { root, decodeCheck: true });
        return accepted();
      } catch (error) {
        return blockedFromThrown(error, 'ERR_PATHCAGE_');
      }
    }
  };
}

function createHeaderAdapter() {
  return {
    async: false,
    invoke(benchCase) {
      try {
        assertSafeHeaderValue(benchCase.input);
        return accepted();
      } catch (error) {
        return blockedFromThrown(error, 'ERR_HEADSAFE_');
      }
    }
  };
}

function createRedirectAdapter() {
  const guard = createRedirectGuard({
    allowedOrigins: ['https://app.example.com']
  });
  return {
    async: false,
    invoke(benchCase) {
      const parsed = guard.parseLocation(benchCase.input);
      return {
        blocked: !parsed.safe,
        signal: parsed.safe ? 'accepted' : parsed.code
      };
    }
  };
}

function createEnvAdapter() {
  const schema = {
    APP_NAME: t.str({ minLength: 1, maxLength: 80 }),
    PUBLIC_URL: t.url({
      requireHttps: true,
      disallowCredentials: true,
      allowedHosts: ['app.example.com']
    }),
    PORT: t.port(),
    API_TOKEN: t.secret({ minLength: 16 }),
    MODE: t.enum(['production', 'development']),
    FEATURES: t.csv({ unique: true, minItems: 1, maxItems: 8 })
  };
  const baseline = Object.freeze({
    APP_NAME: 'Checkout',
    PUBLIC_URL: 'https://app.example.com/',
    PORT: '8080',
    API_TOKEN: 'k9X-synthetic-42Zx-7qwerty',
    MODE: 'production',
    FEATURES: 'search,audit'
  });
  return {
    async: false,
    invoke(benchCase) {
      try {
        defineEnv(schema, { ...baseline, ...benchCase.input }, { maxValueLength: 4096 });
        return accepted();
      } catch (error) {
        return blockedFromThrown(error, 'ERR_ENVCAGE_');
      }
    }
  };
}

function createCookieAdapter() {
  return {
    async: false,
    invoke(benchCase) {
      try {
        parseCookieHeader(benchCase.input);
        return accepted();
      } catch (error) {
        return blockedFromThrown(error, 'ERR_COOKIECAGE_');
      }
    }
  };
}

function createZipAdapter() {
  return {
    async: false,
    prepare(input) {
      return prepareZipInput(input);
    },
    invoke(benchCase) {
      try {
        const archive = createZipBuffer(benchCase.prepared.entries, { validate: false });
        const report = inspectZipBuffer(archive);
        return {
          blocked: !report.safe,
          signal: report.safe ? 'accepted' : (report.findings[0] && report.findings[0].code) || 'unsafe-archive'
        };
      } catch (error) {
        return blockedFromThrown(error, 'ERR_ZIPCAGE_');
      }
    }
  };
}

function createLogAdapter() {
  return {
    async: false,
    invoke(benchCase) {
      const output = sanitizeLogLine(benchCase.input);
      return {
        blocked: output !== benchCase.input,
        signal: output === benchCase.input ? 'unchanged' : 'neutralized',
        outputLength: output.length
      };
    }
  };
}

function createCorsAdapter() {
  const policy = createCorsPolicy({
    allowedOrigins: ['https://app.example.com'],
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['content-type', 'authorization'],
    exposeHeaders: ['x-request-id'],
    maxAge: 600,
    rejectDisallowedPreflight: true
  });
  return {
    async: false,
    invoke(benchCase) {
      const evaluation = policy.evaluate(benchCase.input);
      const nonCorsPassThrough = evaluation.code === 'CORS_NO_ORIGIN';
      return {
        blocked: !evaluation.allowed && !nonCorsPassThrough,
        signal: evaluation.allowed ? 'accepted' : (nonCorsPassThrough ? 'non-cors-pass-through' : evaluation.code)
      };
    }
  };
}

function createJsonAdapter() {
  const cage = createJsonCage({
    maxBytes: 4096,
    maxDepth: 32,
    maxNodes: 5000,
    rejectUnsafeIntegers: true
  });
  return {
    async: false,
    invoke(benchCase) {
      const report = cage.inspect(benchCase.input);
      return {
        blocked: !report.ok,
        signal: report.ok ? 'accepted' : (report.findings[0] && report.findings[0].code) || 'unsafe-json'
      };
    }
  };
}


const JWT_SECRET = '0123456789abcdef0123456789abcdef';
const JWT_NOW = 2000000000;
const CSRF_SECRET = '0123456789abcdef0123456789abcdef';
const CSRF_NOW = 2000000000000;
const HOOK_NOW_MS = 2000000000000;
const HOOK_NOW_SECONDS = Math.floor(HOOK_NOW_MS / 1000);
const HOOK_SECRETS = Object.freeze(['current benchmark webhook secret', 'previous benchmark webhook secret']);
const STANDARD_HOOK_SECRET = 'whsec_' + Buffer.from('benchmark only standard webhook secret', 'utf8').toString('base64');

function jwtBase64(text) {
  return Buffer.from(text, 'utf8').toString('base64url');
}

function manualJwtToken(header, payload) {
  const headerText = typeof header === 'string' ? header : JSON.stringify({ typ: 'JWT', ...header });
  const payloadText = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const signingInput = jwtBase64(headerText) + '.' + jwtBase64(payloadText);
  if (header.alg === 'none') {
    return signingInput + '.';
  }
  const digest = header.alg === 'HS512' ? 'sha512' : header.alg === 'HS384' ? 'sha384' : 'sha256';
  return signingInput + '.' + createHmac(digest, JWT_SECRET).update(signingInput).digest('base64url');
}

function jwtBaseClaims() {
  return {
    iss: 'https://issuer.example',
    aud: 'api',
    sub: 'user-123',
    iat: JWT_NOW - 10,
    exp: JWT_NOW + 300
  };
}

function signBenignJwt(payload, header) {
  return signJwt(payload, JWT_SECRET, {
    algorithm: 'HS256',
    now: JWT_NOW,
    noTimestamp: true,
    header
  });
}

function prepareJwtCase(input) {
  const base = jwtBaseClaims();
  if (input.scenario === 'alg-none') {
    return { token: manualJwtToken({ alg: 'none' }, base) };
  }
  if (input.scenario === 'unlisted-algorithm') {
    return { token: manualJwtToken({ alg: 'HS512' }, base) };
  }
  if (input.scenario === 'dangerous-jku') {
    return { token: manualJwtToken({ alg: 'HS256', jku: 'https://keys.example/jwks.json' }, base) };
  }
  if (input.scenario === 'kid-traversal') {
    return { token: manualJwtToken({ alg: 'HS256', kid: '../keys/current' }, base) };
  }
  if (input.scenario === 'duplicate-payload-key') {
    const rawPayload = '{"iss":"https://issuer.example","aud":"api","iat":' + (JWT_NOW - 10) + ',"exp":' + (JWT_NOW + 300) + ',"role":"user","role":"admin"}';
    return { token: manualJwtToken({ alg: 'HS256' }, rawPayload) };
  }
  if (input.scenario === 'prototype-payload-key') {
    const rawPayload = '{"iss":"https://issuer.example","aud":"api","iat":' + (JWT_NOW - 10) + ',"exp":' + (JWT_NOW + 300) + ',"__proto__":{"admin":true}}';
    return { token: manualJwtToken({ alg: 'HS256' }, rawPayload) };
  }
  if (input.scenario === 'missing-exp') {
    const withoutExpiry = { ...base };
    delete withoutExpiry.exp;
    return { token: manualJwtToken({ alg: 'HS256' }, withoutExpiry) };
  }
  if (input.scenario === 'expired') {
    return { token: manualJwtToken({ alg: 'HS256' }, { ...base, exp: JWT_NOW - 10 }) };
  }
  if (input.scenario === 'valid-basic') {
    return { token: signBenignJwt({ ...base }) };
  }
  if (input.scenario === 'valid-array-audience') {
    return { token: signBenignJwt({ ...base, aud: ['api', 'mobile'] }) };
  }
  if (input.scenario === 'valid-safe-kid') {
    return { token: signBenignJwt({ ...base }, { kid: 'key-2026-01' }) };
  }
  if (input.scenario === 'valid-nbf') {
    return { token: signBenignJwt({ ...base, nbf: JWT_NOW - 5 }) };
  }
  if (input.scenario === 'valid-expiry-boundary') {
    return { token: signBenignJwt({ ...base, exp: JWT_NOW }) };
  }
  if (input.scenario === 'valid-custom-claims') {
    return { token: signBenignJwt({ ...base, scope: ['read'], nested: { plan: 'standard' } }) };
  }
  if (input.scenario === 'valid-jti') {
    return { token: signBenignJwt({ ...base, jti: 'token-001' }) };
  }
  if (input.scenario === 'valid-iat-edge') {
    return { token: signBenignJwt({ ...base, iat: JWT_NOW - 599 }) };
  }
  throw new Error('unknown jwtguard scenario ' + String(input.scenario));
}

function createJwtAdapter() {
  const options = Object.freeze({
    algorithms: ['HS256'],
    now: JWT_NOW,
    clockToleranceSeconds: 5,
    issuer: 'https://issuer.example',
    audience: 'api',
    maxAgeSeconds: 600
  });
  return {
    async: false,
    prepare(input) {
      return prepareJwtCase(input);
    },
    invoke(benchCase) {
      try {
        verifyJwt(benchCase.prepared.token, JWT_SECRET, options);
        return accepted();
      } catch (error) {
        return blockedFromThrown(error, 'ERR_JWTGUARD_');
      }
    }
  };
}

function prepareCsrfCase(input, shield) {
  const scenario = input.scenario || 'valid';
  const expired = scenario === 'expired-token';
  const issueNow = expired ? CSRF_NOW - 7200000 : CSRF_NOW;
  const pair = shield.issueTokenPair({}, {
    sessionId: 'session-one',
    now: issueNow,
    nonce: 'abcdefghijklmnop'
  });
  const otherToken = shield.issueToken({}, {
    sessionId: 'session-one',
    now: issueNow,
    nonce: 'qrstuvwxyzabcdef'
  });
  const tokenMode = input.tokenMode || 'header';
  let submitted = pair.token;
  if (scenario === 'mismatched-token') {
    submitted = otherToken;
  } else if (scenario === 'forged-token') {
    submitted = pair.token.slice(0, -2) + (pair.token.endsWith('aa') ? 'bb' : 'aa');
  } else if (tokenMode === 'masked') {
    submitted = pair.maskedToken;
  }

  const origin = Object.hasOwn(input, 'origin') ? input.origin : 'https://app.example.com';
  const fetchSite = Object.hasOwn(input, 'fetchSite') ? input.fetchSite : 'same-origin';
  const headers = {};
  if (origin !== null && origin !== undefined) {
    headers.origin = origin;
  }
  if (fetchSite !== null && fetchSite !== undefined) {
    headers['sec-fetch-site'] = fetchSite;
  }
  if (typeof input.referer === 'string') {
    headers.referer = input.referer;
  }
  let body;
  if (tokenMode === 'body-object') {
    body = { _csrf: submitted };
  } else if (tokenMode === 'body-form') {
    body = '_csrf=' + encodeURIComponent(submitted);
  } else {
    headers['x-csrf-token'] = submitted;
  }

  return {
    request: {
      method: input.method || 'POST',
      url: 'https://app.example.com/account/transfer',
      headers,
      cookie: scenario === 'missing-cookie' ? undefined : shield.cookie.name + '=' + pair.token,
      body
    },
    settings: {
      sessionId: scenario === 'session-mismatch' ? 'session-two' : 'session-one',
      now: CSRF_NOW
    }
  };
}

function createCsrfAdapter() {
  const shield = createShield({
    secrets: [CSRF_SECRET],
    origin: 'https://app.example.com'
  });
  return {
    async: true,
    prepare(input) {
      return prepareCsrfCase(input, shield);
    },
    async invoke(benchCase) {
      try {
        await shield.verifyRequest(benchCase.prepared.request, benchCase.prepared.settings);
        return accepted();
      } catch (error) {
        if (error && error.name === 'CsrfShieldError') {
          return { blocked: true, signal: error.code };
        }
        throw error;
      }
    }
  };
}

function hookHmacHex(secret, payload) {
  return createHmac('sha256', secret).update(payload).digest('hex');
}

function hookHmacBase64(secret, payload) {
  return createHmac('sha256', secret).update(payload).digest('base64');
}

function hookOptions(provider, publicKeyHex) {
  if (provider === 'standard-webhooks') {
    return { secret: STANDARD_HOOK_SECRET, now: () => HOOK_NOW_MS };
  }
  if (provider === 'discord') {
    return { publicKey: publicKeyHex, now: () => HOOK_NOW_MS };
  }
  return { secrets: HOOK_SECRETS, now: () => HOOK_NOW_MS };
}

function prepareHookCase(input, discordKeys, publicKeyHex) {
  const provider = input.provider;
  const scenario = input.scenario || 'valid';
  const body = input.body;
  const secret = HOOK_SECRETS[0];
  if (provider === 'github') {
    const signingSecret = scenario === 'rotation'
      ? HOOK_SECRETS[1]
      : scenario === 'wrong-signature'
        ? 'wrong benchmark secret'
        : secret;
    let signature = hookHmacHex(signingSecret, body);
    if (scenario === 'malformed-signature') {
      signature = 'z'.repeat(64);
    }
    return {
      provider,
      body,
      headers: { 'x-hub-signature-256': 'sha256=' + signature },
      options: hookOptions(provider, publicKeyHex)
    };
  }
  if (provider === 'stripe') {
    let timestamp = HOOK_NOW_SECONDS;
    if (scenario === 'stale-timestamp') {
      timestamp -= 1000;
    } else if (scenario === 'future-timestamp') {
      timestamp += 1000;
    }
    const signature = hookHmacHex(secret, String(timestamp) + '.' + body);
    return {
      provider,
      body,
      headers: { 'stripe-signature': 't=' + timestamp + ',v1=' + signature },
      options: hookOptions(provider, publicKeyHex)
    };
  }
  if (provider === 'slack') {
    const timestamp = String(HOOK_NOW_SECONDS);
    const signature = hookHmacHex(secret, 'v0:' + timestamp + ':' + body);
    const headers = {
      'x-slack-signature': 'v0=' + signature,
      'x-slack-request-timestamp': timestamp
    };
    if (scenario === 'missing-signature') {
      delete headers['x-slack-signature'];
    }
    return { provider, body, headers, options: hookOptions(provider, publicKeyHex) };
  }
  if (provider === 'shopify') {
    const signature = scenario === 'bad-base64' ? '!!!!' : hookHmacBase64(secret, body);
    return {
      provider,
      body,
      headers: { 'x-shopify-hmac-sha256': signature },
      options: hookOptions(provider, publicKeyHex)
    };
  }
  if (provider === 'linear') {
    const signature = hookHmacHex(secret, body);
    return {
      provider,
      body,
      headers: { 'linear-signature': scenario === 'array-header' ? [signature, signature] : signature },
      options: hookOptions(provider, publicKeyHex)
    };
  }
  if (provider === 'standard-webhooks') {
    const messageId = 'msg-001';
    const timestamp = String(HOOK_NOW_SECONDS);
    const key = Buffer.from(STANDARD_HOOK_SECRET.slice(6), 'base64');
    const signature = createHmac('sha256', key).update(messageId + '.' + timestamp + '.' + body).digest('base64');
    return {
      provider,
      body,
      headers: {
        'webhook-id': messageId,
        'webhook-timestamp': timestamp,
        'webhook-signature': 'v1,' + signature
      },
      options: hookOptions(provider, publicKeyHex)
    };
  }
  if (provider === 'discord') {
    const timestamp = String(HOOK_NOW_SECONDS);
    const signature = ed25519Sign(null, Buffer.from(timestamp + body, 'utf8'), discordKeys.privateKey).toString('hex');
    return {
      provider,
      body,
      headers: {
        'x-signature-ed25519': signature,
        'x-signature-timestamp': timestamp
      },
      options: hookOptions(provider, publicKeyHex)
    };
  }
  throw new Error('unknown hookverify provider ' + String(provider));
}

function deterministicEd25519Keys() {
  const seed = Buffer.alloc(32);
  for (let index = 0; index < seed.length; index += 1) {
    seed[index] = (index * 17 + 29) % 256;
  }
  const privateDer = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const privateKey = createPrivateKey({ key: privateDer, format: 'der', type: 'pkcs8' });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

function createHookAdapter() {
  const discordKeys = deterministicEd25519Keys();
  const publicDer = discordKeys.publicKey.export({ format: 'der', type: 'spki' });
  const publicKeyHex = publicDer.subarray(publicDer.length - 32).toString('hex');
  return {
    async: false,
    prepare(input) {
      const prepared = prepareHookCase(input, discordKeys, publicKeyHex);
      if (input.scenario === 'replayed-delivery') {
        const replayStore = new MemoryReplayStore({ maxEntries: 100, ttlSeconds: 600 });
        prepared.options = { ...prepared.options, replayStore };
        verifyWebhook(prepared.provider, prepared.body, prepared.headers, prepared.options);
      }
      return prepared;
    },
    invoke(benchCase) {
      try {
        verifyWebhook(benchCase.prepared.provider, benchCase.prepared.body, benchCase.prepared.headers, benchCase.prepared.options);
        return accepted('valid');
      } catch (error) {
        if (error && error.name === 'HookVerifyError') {
          return { blocked: true, signal: error.code };
        }
        throw error;
      }
    }
  };
}

function createUrlAdapter() {
  const options = Object.freeze({
    allowedSchemes: ['https:'],
    allowedPorts: 'default-only',
    maxRedirects: 5
  });
  return {
    async: true,
    async invoke(benchCase) {
      const input = benchCase.input;
      const result = input.kind === 'chain'
        ? await validateRedirectChain(input.values, options)
        : validateUrl(input.value, options);
      return {
        blocked: !result.ok,
        signal: result.ok ? 'accepted' : result.code
      };
    }
  };
}

function createRegexAdapter() {
  return {
    async: false,
    invoke(benchCase) {
      const analysis = analyzeRegex(benchCase.input);
      const first = analysis.findings[0];
      return {
        blocked: !analysis.safe,
        signal: analysis.safe ? 'accepted' : (first && first.code) || analysis.risk,
        outputLength: analysis.findings.length
      };
    }
  };
}

function createCsvAdapter() {
  return {
    async: false,
    invoke(benchCase) {
      const report = inspectCsv(benchCase.input, { hasHeader: true });
      const first = report.findings[0];
      return {
        blocked: !report.safe,
        signal: report.safe ? 'accepted' : (first && first.rule) || 'unsafe-csv',
        outputLength: report.findings.length
      };
    }
  };
}

function createHtmlAdapter() {
  const clean = createSanitizer({
    allowedTags: ['p', 'b', 'strong', 'em', 'a', 'ul', 'li'],
    allowedAttributes: { a: ['href', 'title'] },
    allowedSchemes: ['https:'],
    allowRelativeUrls: true
  });
  return {
    async: false,
    invoke(benchCase) {
      try {
        const output = clean.sanitize(benchCase.input);
        return {
          blocked: output !== benchCase.input,
          signal: output === benchCase.input ? 'unchanged' : 'neutralized',
          outputLength: output.length
        };
      } catch (error) {
        if (error && error.name === 'HtmlCleanError') {
          return { blocked: true, signal: error.code };
        }
        throw error;
      }
    }
  };
}

function createSecretsweepAdapter() {
  return {
    async: false,
    invoke(benchCase) {
      const findings = scanText(benchCase.input);
      const first = findings[0];
      return {
        blocked: findings.length > 0,
        signal: first ? first.detector : 'no-findings',
        outputLength: findings.length
      };
    }
  };
}

export function createAdapters(context) {
  return {
    'sentinel-lint': createSentinelAdapter(),
    pathcage: createPathAdapter(context),
    headersafe: createHeaderAdapter(),
    redirectcage: createRedirectAdapter(),
    envcage: createEnvAdapter(),
    cookiecage: createCookieAdapter(),
    zipcage: createZipAdapter(),
    logcage: createLogAdapter(),
    corscage: createCorsAdapter(),
    jsoncage: createJsonAdapter(),
    '@aarivbuildz/jwtguard': createJwtAdapter(),
    '@aarivbuildz/csrfshield': createCsrfAdapter(),
    '@aarivbuildz/hookverify': createHookAdapter(),
    '@aarivbuildz/urlguard': createUrlAdapter(),
    '@aarivbuildz/regex-shield': createRegexAdapter(),
    '@aarivbuildz/csvshield': createCsvAdapter(),
    '@aarivbuildz/htmlclean': createHtmlAdapter(),
    '@aarivbuildz/secretsweep': createSecretsweepAdapter()
  };
}
