import { Env, IncomingPayload, LogEvent } from './types';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'POST' && url.pathname === '/api/v1/logs') {
      const apiKey = request.headers.get('X-API-Key');
      if (apiKey !== env.API_KEY) {
        return new Response('Unauthorized', { status: 401 });
      }

      return new Response(JSON.stringify({ status: 'success', message: 'Logs received' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response('CloudEdge AI SOAR Gateway Active', { status: 200 });
  }
};
