import { Oauth2Scheme } from '@nuxtjs/auth-next'
import {encodeQuery, generateRandomString, normalizePath, getProp, urlJoin, parseQuery, randomString} from './utils'
import requrl from 'requrl'


const SLUG = "CryptrScheme"
const PKCE_STORAGE_KEY = ".pkce_state"
const VERIFIER_STORAGE_KEY = ".pkce_code_verifier"
const AUTH_STATE_KEY = ".state"

export default class CryptrScheme {

  constructor(auth, options) {
    this.$auth = auth
    this.name = options.name
    this.debug('cryptr scheme constructor')

    this.options = Object.assign({}, DEFAULTS, options)
    this.checkOptions()
    this.token = null
    this.refreshToken = null
    this.debug('options', this.options)
  }

  checkOptions() {
    if(this.checkDomain() && this.checkbaseURL() && this.checkClientId()) {
      return
    }
    throw new Error(`${SLUG} options must include 'domain', 'clientId' and 'baseUrl'`)
  }

  checkDomain() {
    return this.options.hasOwnProperty('domain')
  }
  checkbaseURL() {
    return this.options.hasOwnProperty('baseUrl')
  }
  checkClientId() {
    return this.options.hasOwnProperty('clientId')
  }

  async mounted() {
    this.debug("mounted")
    // const { tokenExpired, refreshTokenExpired } = this.check(true)
    const redirected = await this._handleCallback()
    this.debug("redirected", redirected)
    if(!redirected) {
      return this.$auth.fetchUserOnce()
    }
  }


  async _handleCallback() {
    this.debug('handleCallback')
    if (
      this.$auth.options.redirect &&
      normalizePath(this.$auth.ctx.route.path, this.$auth.ctx) !==
        normalizePath(this.$auth.options.redirect.callback, this.$auth.ctx)
    ) {
      return
    }
    // Callback flow is not supported in server side
    if (process.server) {
      return
    }
    this.debug("callback guard excluded")

    const hash = parseQuery(this.$auth.ctx.route.hash.substr(1))
    const parsedQuery = Object.assign({}, this.$auth.ctx.route.query, hash)
    this.debug('parsedQuery', parsedQuery)
    this.debug('parsedQuery', Object.keys(parsedQuery))

    let token = parsedQuery[this.options.token.property]
    this.debug('token', token)

    let refreshToken

    if (this.options.refreshToken.property) {
      refreshToken = parsedQuery[this.options.refreshToken.property]
    }
    this.debug('refreshToken', refreshToken)

    // TODO: Fetch state and verifier from db
    const state = this.$auth.$storage.getUniversal(this.name + AUTH_STATE_KEY)
    this.$auth.$storage.setUniversal(this.name + AUTH_STATE_KEY, null)

    const pkceState = this.$auth.$storage.getUniversal(this.name + PKCE_STORAGE_KEY)
    this.debug('pkceState', pkceState)
    if (!pkceState || !pkceState.length) {
      console.info(SLUG, 'Not going forward because pkce state unknown')
      return
    }
    this.$auth.$storage.setUniversal(this.name + PKCE_STORAGE_KEY, null)
    const codeVerifier = this.$auth.$storage.getUniversal(this.name + VERIFIER_STORAGE_KEY)
    this.$auth.$storage.setUniversal(this.name + VERIFIER_STORAGE_KEY, null)


    const domain = parsedQuery['organization_domain'] || this.options.domain
    const signType = 'sso'
    const authId = parsedQuery['authorization_id']
    const authCode = parsedQuery['authorization_code']
    this.debug('authId', authId)
    this.debug('authCode', authCode)
    const requestData = {
        authorization_id: authId,
        code: authCode,
        client_id: this.options.clientId + '',
        redirect_uri: this.redirectURI(),
        responseType: this.options.resposeType,
        audience: this.options.audience,
        grant_type: this.options.grantType,
        client_state: pkceState,
        code_verifier: codeVerifier
      }
      this.debug(requestData)
    const response = await this.$auth.request({
      method: 'post',
      baseURL: this.options.baseUrl,
      url: `/api/v1/tenants/${domain}/${this.options.clientId}/oauth/${signType}/client/token`,
      data: encodeQuery(requestData)

    })

    this.debug(response)
    token = getProp(response.data, this.options.token.property) || token
    this.debug('token', token)
    refreshToken =
    (getProp(
      response.data,
      this.options.refreshToken.property
      )) || refreshToken
    this.debug('refreshToken', refreshToken)

    if(!token || !token.length) {
      return
    }

    this.token = token

    if(refreshToken && refreshToken.length) {
      this.refreshToken = refreshToken
    }
    this.debug('watchLoggedIn', this.$auth.options.watchLoggedIn)
    if(this.$auth.options.watchLoggedIn) {
      this.$auth.redirect('home', true)
      return true
    }

    return Promise.resolve();
  }

  async login(params) {
    this.debug('login')
    this.debug('params', params)
    if(params) {
      const { data } = params
      this.debug(data)
    }
    this.debug('options', this.options)
    this.debug('endpoints', this.options.endpoints)
    await this.$auth.reset();
    const url = await this.loginUrl(params)
    this.debug(url)
    window.location.replace(url)
  }

  async logout(){
    this.debug('logout', this)
    return this.$auth.reset()
  }

  async reset() {
    this.debug('reset')
    return Promise.resolve()
  }

  async fetchUser() {
    this.debug("fetchUser")
    this.debug("check valid", this.check().valid)
    if (!this.check().valid) {
      return
    }

    if (!this.options.endpoints.userInfo) {
      this.$auth.setUser({})
      return
    }

    const response = await this.$auth.requestWith(this.name, {
      url: this.options.endpoints.userInfo
    })

    this.$auth.setUser(getProp(response.data, this.options.user.property))
  }

  // HELPERS

  debug(...args) {
    console.debug(SLUG, ...args)
  }

  async refreshToken() {
    this.debug('refreshToken')
    return Promise.resolve()
  }

  redirectURI() {
    const basePath = this.$auth.ctx.base || ''
    const path = normalizePath(
      basePath + '/' + this.$auth.options.redirect.callback
    ) // Don't pass in context since we want the base path
    return this.options.redirectUri || urlJoin(requrl(this.req), path)
  }

  gatewayRootUrl() {
    return this.options.isDedicatedDomain ? this.options.baseUrl : this.options.baseUrl + '/t/' + this.options.domain
  }

  genAndStoreState() {
    const state = generateRandomString()
    this.$auth.$storage.setUniversal(this.name + PKCE_STORAGE_KEY, state)
    return state
  }

  genAndStoreVerifier() {
    const verifier = generateRandomString()
    this.$auth.$storage.setUniversal(this.name + VERIFIER_STORAGE_KEY, verifier)
    return verifier
  }

  async pkceChallengeFromVerifier(verifier) {
    const hashed = await this._sha256(verifier)
    return this._base64UrlEncode(hashed)
  }

  async loginUrl({data}) {
    const codeVerifier = this.genAndStoreVerifier()
    const codeChallenge = await this.pkceChallengeFromVerifier(codeVerifier)
    const opts = {
      client_id: this.options.clientId,
      redirect_uri: this.redirectURI(),
      client_state: this.genAndStoreState(),
      nonce: randomString(10),
      scope: data.scope || this.options.scope.join(' '),
      code_challenge_method: this.options.codeChallengeMethod,
      code_challenge: codeChallenge
    }
    this.$auth.$storage.setUniversal(this.name + AUTH_STATE_KEY, opts.state)
    const rawGatewayUrl = this.gatewayRootUrl() + '?' + encodeQuery(opts)
    this.debug('provided options for login', data)
    return (data && data.idpIds) ? (rawGatewayUrl + '&idp_ids[]=' + data.idpIds.join('&idp_ids[]=')) : rawGatewayUrl
  }



  _sha256(plain) {
    const encoder = new TextEncoder()
    const data = encoder.encode(plain)
    return window.crypto.subtle.digest('SHA-256', data)
  }

  _base64UrlEncode(str) {
    // Convert the ArrayBuffer to string using Uint8 array to convert to what btoa accepts.
    // btoa accepts chars only within ascii 0-255 and base64 encodes them.
    // Then convert the base64 encoded to base64url encoded
    //   (replace + with -, replace / with _, trim trailing =)
    return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')
  }
}

const DEFAULTS = {
  token: {
    property: 'access_token',
    type: 'Bearer',
    maxAge: 1800
  },
  refreshToken: {
    property: 'refresh_token',
    maxAge: 60 * 60 * 24 * 30
  },
  codeChallengeMethod: 'S256',
  isDedicatedDomain: false,
  scope: ['openid', 'email', 'profile'],
  responseType: 'code',
  grantType: 'authorization_code',
  autoLogout: true,
  responseMode: '',
  acrValues: '',
}
