export default {
  // Global page headers: https://go.nuxtjs.dev/config-head
  head: {
    title: 'cryptr-nuxt-sample',
    htmlAttrs: {
      lang: 'en'
    },
    meta: [
      { charset: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { hid: 'description', name: 'description', content: '' },
      { name: 'format-detection', content: 'telephone=no' }
    ],
    link: [
      { rel: 'icon', type: 'image/x-icon', href: '/favicon.ico' }
    ]
  },
  auth: {
    strategies: {
      local: {
        token: {
          property: 'token',
          global: true,
          // required: true,
          // type: 'Bearer'
        },
        user: {
          property: 'user',
          // autoFetch: true
        },
        endpoints: {
          login: { url: '/api/auth/login', method: 'post' },
          logout: { url: '/api/auth/logout', method: 'post' },
          user: { url: '/api/auth/user', method: 'get' }
        }
      },
      cryptr: {
        scheme: 'oauth2',
        endpoints: {
          authorization: `${process.env.CRYPTR_BASE_URL}/?idp_ids[]=${process.env.CRYPTR_IDP_IDS && process.env.CRYPTR_IDP_IDS.split(',').join("&idp_ids[]=")}`,
          token: `${process.env.CRYPTR_BASE_URL}/api/v1/tenants/blockpulse/${process.env.CRYPTR_CLIENT_ID}/oauth/sso/client/token`,
          userInfo: `${process.env.CRYPTR_BASE_URL}/t/blockpulse/userinfo?client_id=${process.env.CRYPTR_CLIENT_ID}`,
          // logout: `${process.env.CRYPTR_BASE_URL}/api/v1/tenants/blockpulse/oauth/token/revoke`,
          logout: {
            baseURL: process.env.CRYPTR_BASE_URL,
            url: '/api/v1/tenants/blockpulse/oauth/token/revoke',
            method: 'post'
          },
        },
        token: {
          property: 'access_token',
          type: 'Bearer',
          maxAge: 1800
        },
        refreshToken: {
          property: 'refresh_token',
          maxAge: 60 * 60 * 24 * 30
        },
        responseType: 'code',
        grantType: 'authorization_code',
        clientId: process.env.CRYPTR_CLIENT_ID,
        scope: ['openid', 'profile', 'email'],
        codeChallengeMethod: 'S256',
        responseMode: '',
        acrValues: '',
        autoLogout: true
      },
      google: {
        clientId: process.env.GOOGLE_API_CLIENT_ID,
        codeChallengeMethod: '',
        responseType: 'code',
        redirectUri: 'http://localhost:3000/login',
        // endpoints: {
        //   token: 'http://localhost:8000/user/google/', // somm backend url to resolve your auth with google and give you the token back
        //   userInfo: 'http://localhost:8000/auth/user/' // the endpoint to get the user info after you recived the token
        // },
      },
      auth0: {
        domain: process.env.AUTH0_DOMAIN,
        clientId: process.env.AUTH0_CLIENT_ID,
        audience: process.env.AUTH0_AUDIENCE,
        scope: ['openid', 'profile', 'email', 'offline_access'],
        responseType: 'code',
        grantType: 'authorization_code',
        codeChallengeMethod: 'S256',
        // redirectUri: 'http://localhost:3000/login'
      },
    }
  },

  // Global CSS: https://go.nuxtjs.dev/config-css
  css: [
  ],

  // Plugins to run before rendering page: https://go.nuxtjs.dev/config-plugins
  plugins: [
  ],

  // Auto import components: https://go.nuxtjs.dev/config-components
  components: true,

  // Modules for dev and build (recommended): https://go.nuxtjs.dev/config-modules
  buildModules: [
    // https://go.nuxtjs.dev/typescript
    '@nuxt/typescript-build',
    // https://go.nuxtjs.dev/tailwindcss
    '@nuxtjs/tailwindcss',
  ],

  // Modules: https://go.nuxtjs.dev/config-modules
  modules: [
    '@nuxtjs/axios',
    '@nuxtjs/auth-next'
  ],

  // Build Configuration: https://go.nuxtjs.dev/config-build
  build: {
  },
  router: {
    middleware: ['auth']
  }
}
