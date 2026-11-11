
const OWNER = 'buiattegit';
const REPO = 'Reabastecimento_';
const BRANCH = 'main';
const FILE = 'skus_monitorados.json';

const GH = `https://api.github.com/repos/${OWNER}/${REPO}/contents/${FILE}`;

const responseHeaders = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff'
};

function reply(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: responseHeaders
  });
}

function githubHeaders(env) {
  return {
    Authorization: `Bearer ${env.GITHUB_TOKEN}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'buiatte-reabastecimento'
  };
}

async function readGithub(env) {
  const response = await fetch(`${GH}?ref=${BRANCH}`, {
    headers: githubHeaders(env),
    cache: 'no-store'
  });

  if (!response.ok) {
    throw new Error(`GitHub leitura HTTP ${response.status}`);
  }

  const file = await response.json();
  const raw = atob(String(file.content || '').replace(/\s/g, ''));
  const bytes = Uint8Array.from(raw, c => c.charCodeAt(0));
  const cfg = JSON.parse(new TextDecoder().decode(bytes));

  if (!Array.isArray(cfg.skus)) {
    throw new Error('Arquivo de configuração sem lista skus');
  }

  return { cfg, sha: file.sha };
}

function base64Utf8(s) {
  const bytes = new TextEncoder().encode(s);
  let out = '';

  for (const b of bytes) {
    out += String.fromCharCode(b);
  }

  return btoa(out);
}

function fromBase64Url(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(
    normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=')
  );

  return Uint8Array.from(raw, c => c.charCodeAt(0));
}

function decodeJwtPart(value) {
  return JSON.parse(
    new TextDecoder().decode(fromBase64Url(value))
  );
}

async function accessAuthorized(request, env) {
  const domain = String(env.ACCESS_TEAM_DOMAIN || '')
    .trim()
    .replace(/^https?:\/\//, '')
    .replace(/\/$/, '');

  const audience = String(env.ACCESS_AUD || '').trim();

  if (
    !domain ||
    !audience ||
    !/^[a-zA-Z0-9.-]+\.cloudflareaccess\.com$/.test(domain)
  ) {
    return false;
  }

  const token = request.headers.get('Cf-Access-Jwt-Assertion');

  if (!token) return false;

  const parts = token.split('.');

  if (parts.length !== 3) return false;

  try {
    const header = decodeJwtPart(parts[0]);
    const payload = decodeJwtPart(parts[1]);
    const now = Math.floor(Date.now() / 1000);

    if (
      header.alg !== 'RS256' ||
      !header.kid ||
      !payload.exp ||
      payload.exp <= now ||
      !payload.iat ||
      payload.iat > now + 60
    ) {
      return false;
    }

    const expectedIssuer = `https://${domain}`;

    const audiences = Array.isArray(payload.aud)
      ? payload.aud
      : [payload.aud];

    if (
      payload.iss !== expectedIssuer ||
      !audiences.includes(audience)
    ) {
      return false;
    }

    const keysResponse = await fetch(
      `https://${domain}/cdn-cgi/access/certs`,
      {
        cf: {
          cacheTtl: 300,
          cacheEverything: true
        }
      }
    );

    if (!keysResponse.ok) return false;

    const keys = await keysResponse.json();

    const jwk = (keys.keys || []).find(
      k => k.kid === header.kid && k.kty === 'RSA'
    );

    if (!jwk) return false;

    const key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256'
      },
      false,
      ['verify']
    );

    return await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      key,
      fromBase64Url(parts[2]),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
    );
  } catch (_) {
    return false;
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname !== '/api/config') {
      return env.ASSETS.fetch(request);
    }

    if (!env.GITHUB_TOKEN) {
      return reply({
        error: 'Configure GITHUB_TOKEN nos Secrets do Worker.'
      }, 503);
    }

    if (request.method === 'GET') {
      try {
        const { cfg } = await readGithub(env);
        return reply(cfg);
      } catch (e) {
        return reply({ error: e.message }, 502);
      }
    }

    if (request.method !== 'PUT') {
      return new Response('Método não permitido', {
        status: 405,
        headers: { Allow: 'GET, PUT' }
      });
    }

    if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) {
      return reply({
        error: 'Edição desabilitada: configure ACCESS_TEAM_DOMAIN e ACCESS_AUD e proteja a rota com Cloudflare Access.'
      }, 503);
    }

    if (!(await accessAuthorized(request, env))) {
      return reply({
        error: 'Acesso não autorizado. Entre pelo Cloudflare Access.'
      }, 403);
    }

    if (Number(request.headers.get('content-length') || 0) > 20000) {
      return reply({ error: 'Requisição muito grande' }, 413);
    }

    try {
      const body = await request.json();

      if (
        !body ||
        !Array.isArray(body.skus) ||
        body.skus.length > 10000
      ) {
        return reply({ error: 'Lista de SKUs inválida' }, 400);
      }

      const skus = [
        ...new Set(
          body.skus.map(v => String(v).trim().toUpperCase())
        )
      ].sort();

      if (
        skus.some(
          v => !v ||
          v.length > 100 ||
          !/^[A-Z0-9._\/-]+$/.test(v)
        )
      ) {
        return reply({ error: 'SKU com formato inválido' }, 400);
      }

      const { cfg, sha } = await readGithub(env);

      // Preserva os mínimos e demais configurações.
      const updated = { ...cfg, skus };

      const res = await fetch(GH, {
        method: 'PUT',
        headers: {
          ...githubHeaders(env),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          message: 'Atualiza SKUs monitorados pelo painel',
          content: base64Utf8(
            JSON.stringify(updated, null, 2) + '\n'
          ),
          sha,
          branch: BRANCH
        })
      });

      if (!res.ok) {
        return reply({
          error: `GitHub gravação HTTP ${res.status}`,
          detail: (await res.text()).slice(0, 300)
        }, res.status === 409 ? 409 : 502);
      }

      return reply({
        ok: true,
        skus,
        quantidade: skus.length
      });

    } catch (e) {
      return reply({
        error: e.message || 'Erro interno'
      }, 500);
    }
  }
};
