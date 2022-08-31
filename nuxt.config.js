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
      cryptr: {
        scheme: '~schemes/cryptrScheme.js',
        baseUrl: process.env.CRYPTR_BASE_URL,
        domain: 'cryptr',
        audience: 'http://localhost:3000',
        clientId: process.env.CRYPTR_CLIENT_ID,
        isDedicatedDomain: true,
      },
    },
    cookie: false,
    // localStorage: false,
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
    extend (config, { isDev, isClient }) {

       config.node= {
          fs: 'empty'
        }

       // ....
    }
  },
  router: {
    middleware: ['auth']
  },
  serverMiddleware: [
    {path: '/cryptr', handler: "~/api/index.js"}
  ]
}
