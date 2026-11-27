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
    jsoncage: createJsonAdapter()
  };
}
