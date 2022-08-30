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

to start a Cryptr process with Nuxt-Auth use the following pattern:

```js
await this.$auth.loginWith('cryptr', { attrs: /*your_custom_attrs*/})
```

Several Options are available in `attrs` object, such as `locale` or even `redirectUri`, contact us for more

#### SSO

If you are interested in our SSO solution call the below code

```js
await this.$auth.loginWith('cryptr', { attrs: { type: 'sso' } })
```

If you would like to precise what SSO connections to display you can call like this:

```js
await this.$auth.loginWith('cryptr', { attrs: { type: 'sso' , idpIds: ['sso_connection_1', 'sso_connection_2']} })
```

#### Magic Link

If you prefer to log in with our magic link solution use below

```js
await this.$auth.loginWith('cryptr', { attrs: { type: 'signin' } }) // 'signup' is also available
```

### Other actions

You can refresh by `this.$auth.refreshTokens()` and log out with `this.$auth.logout()`
