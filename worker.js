
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
  const raw = atob(
    String(file.content || '').replace(/\s/g, '')
  );

  const bytes = Uint8Array.from(
    raw,
    c => c.charCodeAt(0)
  );

  const cfg = JSON.parse(
    new TextDecoder().decode(bytes)
  );

  if (!Array.isArray(cfg.skus)) {
    throw new Error(
      'Arquivo de configuração sem lista skus'
    );
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

// Autoriza gravações somente a partir dos IPs cadastrados.
// Configure ALLOWED_EDITOR_IPS no Cloudflare.
// Separe vários IPs públicos por vírgula.
function editorAuthorized(request, env) {
  const allowed = String(
    env.ALLOWED_EDITOR_IPS || ''
  )
    .split(',')
    .map(ip => ip.trim())
    .filter(Boolean);

  if (!allowed.length) {
    return false;
  }

  const clientIp = String(
    request.headers.get('CF-Connecting-IP') || ''
  ).trim();

  return allowed.includes(clientIp);
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

    // Todos podem consultar a lista compartilhada.
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
        headers: {
          Allow: 'GET, PUT'
        }
      });
    }

    // A gravação permanece bloqueada sem IP autorizado.
    if (!env.ALLOWED_EDITOR_IPS) {
      return reply({
        error: 'Gravação desabilitada: configure ALLOWED_EDITOR_IPS no Cloudflare.'
      }, 503);
    }

    if (!editorAuthorized(request, env)) {
      return reply({
        error: 'Edição não autorizada nesta rede. Verifique ALLOWED_EDITOR_IPS.'
      }, 403);
    }

    if (
      Number(
        request.headers.get('content-length') || 0
      ) > 20000
    ) {
      return reply({
        error: 'Requisição muito grande'
      }, 413);
    }

    try {
      const body = await request.json();

      if (
        !body ||
        !Array.isArray(body.skus) ||
        body.skus.length > 10000
      ) {
        return reply({
          error: 'Lista de SKUs inválida'
        }, 400);
      }

      const skus = [
        ...new Set(
          body.skus.map(
            v => String(v).trim().toUpperCase()
          )
        )
      ].sort();

      if (
        skus.some(
          v =>
            !v ||
            v.length > 100 ||
            !/^[A-Z0-9._\/-]+$/.test(v)
        )
      ) {
        return reply({
          error: 'SKU com formato inválido'
        }, 400);
      }

      const { cfg, sha } = await readGithub(env);

      // Mantém os mínimos e demais configurações.
      const updated = {
        ...cfg,
        skus
      };

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
