# fastify-auth0-login

A Fastify plugin for easily adding login feature via Auth0's [Authorization Code Flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow).

## Prerequisites

- Fasyify v4.x+
- [@fastify/cookie](https://github.com/fastify/fastify-cookie)

## Usage

First, you need to create a Auth0 application.

Confirm the `Domain`, `Client ID`, and `Client Secret` then set you application's `Login URL`, `Allowed Callback URL`, and `Allowd Web Origins`.

For example to set for `https://localhost:3000`,

![Example Callback URLs](https://user-images.githubusercontent.com/9696352/222125267-76e435f6-6874-48fa-872e-99fbcf87148f.png)

Then configure your Fastify app with this plugin and `@fastify/cookie` like this:

```ts
import FastifyCookie from '@fastify/cookie';
import FastifyAuth0Login from 'fastify-auth0-login';

app.register(FastifyCookie, {
  secret: COOKIE_SECRET,
});

app.register(FastifyAuth0Login, {
  auth0: {
    domin: YOUR_AUTH0_DOMAIN,
    clientId: YOUR_AUTH0_CLIENT_ID,
    clientSecret: YOUR_AUTH0_CLIENT_SECRET,
  },
  verifySession: (_req, sessionId) => {
    return findSession(sessionId);
  },
  confirmSession: (_req, sessionId, idTokenClaims) => {
    return findOrCreateSession(sessionId, idTokenClaims);
  },
});
```

Now you can initiate auth flow by GET `/auth/request`.

```html
<!-- In your /login page HTML -->
<!-- This will redirect user to the Auth0 application's auth URL -->
<a href="/auth">Login with Auth0</a>
```

## LICENSE

MIT
