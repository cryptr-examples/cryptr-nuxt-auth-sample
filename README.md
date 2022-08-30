# cryptr-nuxt-sample

This Repository intends to help you integrate Cryptr in a NuxtJS app using Nuxt-Auth.

You can start with a few steps in your project.

## 1. Cryptr Scheme

We achieved to build a custom Nuxt Auth Scheme for Cryptr [See related file](https://github.com/cryptr-examples/cryptr-nuxt-auth-sample/tree/develop/schemes/cryptrScheme.js)

To use it, copy/paste all content of `schemes` folder in your project.

## 2. Setup your nuxt auth configuration for Cryptr

```js
// nuxt.config.js

export default {
  auth: {
    strategies: {
      cryptr: {
        scheme: '~schemes/cryptrScheme.js',
        baseUrl: process.env.CRYPTR_BASE_URL,
        domain: 'your-master-domain',
        audience: 'http://localhost:3000',
        clientId: process.env.CRYPTR_CLIENT_ID,
        isDedicatedDomain: true
      }
    }
  }
}
```

### 3. Start Cryptr Login Process

to start a Cryptr process with Nuxt-Auth use following pattern:

```js
await this.$auth.loginWith('cryptr', { attrs: /*your_custom_attrs*/})
```

#### Magic Link

If you
