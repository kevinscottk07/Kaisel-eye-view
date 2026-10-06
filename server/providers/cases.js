import path from 'node:path';
import { promises as fsp } from 'node:fs';

import { readRequestBody } from './common/request.js';

/**
 * Case persistence: the link-analysis "case board" is a saved subgraph of
 * threat entities plus the analyst's annotations. Cases are the user's own
 * work, so they are stored as JSON files on disk (not the ephemeral feed
 * cache) and survive restarts.
 *
 * Routes:
 *   GET    /api/cases            → [{id, name, updatedAt, nodeCount}]
 *   POST   /api/cases            → create {name} → the new case
 *   GET    /api/cases/<id>       → the full case
 *   PUT    /api/cases/<id>       → replace the case body
 *   DELETE /api/cases/<id>       → remove it
 *
 * A case is { id, name, createdAt, updatedAt, nodes, edges, assessment }.
 * Node/edge shapes are owned by the client; the server only persists them.
 *
 * @returns {import('vite').Plugin}
 */
export function casesProxy() {
  const DIR = path.join(process.cwd(), '.gev-cases');
  const idPattern = /^[a-z0-9-]{1,64}$/;

  const sendJson = (res, status, body) => {
    if (res.headersSent) return;
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    });
    res.end(JSON.stringify(body));
  };

  const filePath = (id) => path.join(DIR, `${id}.json`);

  async function readCase(id) {
    try {
      return JSON.parse(await fsp.readFile(filePath(id), 'utf8'));
    } catch {
      return null;
    }
  }

  async function writeCase(record) {
    await fsp.mkdir(DIR, { recursive: true });
    await fsp.writeFile(filePath(record.id), JSON.stringify(record), 'utf8');
  }

  async function listCases() {
    let files = [];
    try {
      files = (await fsp.readdir(DIR)).filter((f) => f.endsWith('.json'));
    } catch {
      return [];
    }
    const out = [];
    for (const file of files) {
      try {
        const record = JSON.parse(
          await fsp.readFile(path.join(DIR, file), 'utf8'),
        );
        out.push({
          id: record.id,
          name: record.name,
          updatedAt: record.updatedAt || null,
          nodeCount: Array.isArray(record.nodes) ? record.nodes.length : 0,
        });
      } catch {
        /* skip unreadable case */
      }
    }
    out.sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
    return out;
  }

  const newId = () =>
    `case-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;

  function sanitizeBody(body, existing) {
    const now = new Date().toISOString();
    return {
      id: existing.id,
      name:
        typeof body.name === 'string' && body.name.trim()
          ? body.name.trim().slice(0, 120)
          : existing.name,
      createdAt: existing.createdAt,
      updatedAt: now,
      nodes: Array.isArray(body.nodes)
        ? body.nodes.slice(0, 2000)
        : existing.nodes,
      edges: Array.isArray(body.edges)
        ? body.edges.slice(0, 4000)
        : existing.edges,
      assessment:
        body.assessment && typeof body.assessment === 'object'
          ? body.assessment
          : existing.assessment || null,
    };
  }

  const install = (middlewares) => {
    middlewares.use('/api/cases', async (req, res, next) => {
      try {
        const [subPath] = String(req.url || '').split('?');
        const id = subPath.replace(/^\//, '');

        // Collection: /api/cases
        if (!id) {
          if (req.method === 'GET') {
            sendJson(res, 200, { cases: await listCases() });
            return;
          }
          if (req.method === 'POST') {
            const body = JSON.parse(
              (await readRequestBody(req, 1024 * 1024)) || '{}',
            );
            const now = new Date().toISOString();
            const record = {
              id: newId(),
              name:
                typeof body.name === 'string' && body.name.trim()
                  ? body.name.trim().slice(0, 120)
                  : 'Untitled case',
              createdAt: now,
              updatedAt: now,
              nodes: [],
              edges: [],
              assessment: null,
            };
            await writeCase(record);
            sendJson(res, 201, record);
            return;
          }
          sendJson(res, 405, { error: 'Method not allowed' });
          return;
        }

        // Item: /api/cases/<id>
        if (!idPattern.test(id)) {
          sendJson(res, 400, { error: 'Invalid case id' });
          return;
        }
        const existing = await readCase(id);
        if (req.method === 'GET') {
          if (!existing) {
            sendJson(res, 404, { error: 'Case not found' });
            return;
          }
          sendJson(res, 200, existing);
          return;
        }
        if (req.method === 'PUT') {
          if (!existing) {
            sendJson(res, 404, { error: 'Case not found' });
            return;
          }
          const body = JSON.parse(
            (await readRequestBody(req, 4 * 1024 * 1024)) || '{}',
          );
          const record = sanitizeBody(body, existing);
          await writeCase(record);
          sendJson(res, 200, record);
          return;
        }
        if (req.method === 'DELETE') {
          try {
            await fsp.unlink(filePath(id));
          } catch {
            /* already gone */
          }
          sendJson(res, 200, { ok: true });
          return;
        }
        sendJson(res, 405, { error: 'Method not allowed' });
      } catch (err) {
        console.warn('[cases] error:', err?.message || err);
        sendJson(res, 500, { error: 'cases provider error' });
      }
    });
  };

  return {
    name: 'cases-proxy',
    configureServer(server) {
      install(server.middlewares);
    },
    configurePreviewServer(server) {
      install(server.middlewares);
    },
  };
}
