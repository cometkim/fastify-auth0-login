import { type FastifyPluginCallback, type FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import type {} from '@fastify/cookie';
import { createDecoder } from 'fast-jwt';

export interface FastifySession {
  id: string,
  idSubject: string,
}

export type Auth0IdTokenClaims = {
  nickname?: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
  picture?: string;
  updated_at: string;
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  sid: string;
};

export type Auth0Config = {
  /**
   * Domain for Auth0 Application
   */
  domain: string,

  /**
   * Client ID for Auth0 Application
   */
  clientId: string,

  /**
   * Client Secret for Auth0 Application
   */
  clientSecret: string,

  /**
   * OAuth 2.0 authorization scope
   *
   * @default "openid profile"
   */
  scope?: string,
};

export type FastifyAuth0LoginOptions = {
  /**
   * Fetch implementation
   *
   * @default globalThis.fetch
   */
  fetch?: typeof fetch,

  /**
   * A URL path to get home page
   *
   * @default "/"
   */
  userPath?: string,

  /**
   * A URL path to get login page
   *
   * @default "/login"
   */
  loginPath?: string,

  /**
   * A URL path to start the Authorization Code Flow via Auth0
   *
   * @default "/auth/request"
   */
  authRequestPath?: string,

  /**
   * A URL path to get Authorization Code Flow callback via Auth0
   *
   * @default "/auth/callback"
   */
  authCallbackPath?: string,

  /**
   * Name for Session ID
   *
   * @default "sessionId"
   */
  cookieName?: string,

  /**
   * A predicate function to determine whether the `currentSession` request hook
   *
   * @default () => true
   */
  requireSession?: (req: FastifyRequest) => boolean,

  /**
   * Find session 
   *
   * Plugin will attempts to create a new session if it returns null
   */
  verifySession: (req: FastifyRequest, sessionId: string) => Promise<FastifySession | null>,

  /**
   * Find or create session
   *
   * Authorization flow will be rejected if it returns null
   *
   * Note: It should also connect account with `idTokenClaims.sub` if it creates a new one.
   */
  confirmSession: (req: FastifyRequest, sessionId: string, idTokenClaims: Auth0IdTokenClaims) => Promise<FastifySession | null>,

  /**
   * Configuration for Auth0
   */
  auth0: Auth0Config,
};

const fastifyAuth0LoginPlugin: FastifyPluginCallback<FastifyAuth0LoginOptions> = (
  fastify,
  {
    fetch,
    userPath = '/',
    loginPath = '/login',
    authRequestPath = '/auth/request',
    authCallbackPath = '/auth/callback',
    cookieName = 'sessionId',
    verifySession,
    confirmSession,
    requireSession = () => true,
    auth0: auth0Config,
  },
  done,
) => {
  const decodeJWT = createDecoder();

  const baseURL = new URL(`https://${auth0Config.domain}`);
  const authorizeURL = new URL('/authorize', baseURL);
  const tokenURL = new URL('/oauth/token', baseURL);

  // Redirect to user's login request to the Auth0's Authorization Code Flow
  fastify.route({
    method: 'GET',
    url: authRequestPath,
    schema: {
      querystring: {
        type: 'object',
        properties: {
          redirect_to: { type: 'string' },
        },
      },
    },
    async handler(req, reply) {
      const query = req.query as { redirect_to?: string };
      const self = new URL(authRequestPath, `${req.protocol}://${req.hostname}`);
    
      const redirectUrl = new URL(authCallbackPath, self);
      if (query.redirect_to) {
        redirectUrl.searchParams.set('redirect_to', query.redirect_to);
      }
      
      const target = new URL(authorizeURL);
      target.searchParams.set('response_type', 'code');
      target.searchParams.set('client_id', auth0Config.clientId);
      target.searchParams.set('redirect_uri', redirectUrl.toString());
      target.searchParams.set('scope', auth0Config.scope || 'openid profile');

      reply.redirect(307, target.toString());
    },
  })

  // Callback for Auth0's Authorization Code Flow
  fastify.route({
    method: 'GET',
    url: authCallbackPath,
    schema: {
      querystring: {
        type: 'object',
        properties: {
          code: { type: 'string' },
          redirect_to: { type: 'string' },
        },
        required: ['code'],
      },
    },
    async handler(req, reply) {
      const query = req.query as { code: string; redirect_to?: string };
      const self = new URL(authCallbackPath, `${req.protocol}://${req.hostname}`);

      const response = await fetch(tokenURL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: auth0Config.clientId,
          client_secret: auth0Config.clientSecret,
          code: query.code,
          redirect_uri: self.toString(),
        }),
      });

      const data = await response.json() as {
        access_token: string;
        id_token: string;
        scope: string;
        expires_in: number;
        token_type: 'Bearer';
      };
      const decoded = decodeJWT(data.id_token) as Auth0IdTokenClaims;

      const session = await confirmSession(req, decoded.sid, decoded);
      if (!session) {
        return reply.redirect(401, loginPath);
      }

      reply.setCookie(cookieName, session.id, { path: '/', expires: new Date(decoded.exp) });

      if (query.redirect_to) {
        reply.redirect(query.redirect_to);
      } else {
        reply.redirect(userPath);
      }
    },
  });

  fastify
    .decorateRequest('currentSession', null)
    .addHook('onRequest', async req => {
      if (!requireSession(req)) {
        return;
      }
      if (req.cookies[cookieName]) {
        req.currentSession = await verifySession(req, req.cookies[cookieName]);
      }
    });

  done();
};

export default fp(fastifyAuth0LoginPlugin, {
  name: 'fastify-auth0-login',
  fastify: '4.x',
  dependencies: [
    '@fastify/cookie',
  ],
});

declare module 'fastify' {
  interface FastifyRequest {
    currentSession: FastifySession | null;
  }
}
