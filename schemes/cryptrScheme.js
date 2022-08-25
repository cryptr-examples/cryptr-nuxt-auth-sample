import { Oauth2Scheme } from '@nuxtjs/auth-next'
import {encodeQuery, generateRandomString, normalizePath, getProp, urlJoin, parseQuery, randomString} from './utils'
import requrl from 'requrl'


const SLUG = "CryptrScheme"
const PKCE_STORAGE_KEY = ".pkce_state"
const VERIFIER_STORAGE_KEY = ".pkce_code_verifier"
const AUTH_STATE_KEY = ".state"
const TEMP_TOKEN = 'eyJhbGciOiJSUzI1NiIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMC90L2Jsb2NrcHVsc2UiLCJraWQiOiIwZTFhZTE1Yi1iMGIxLTQ4ZTEtOGY2OS04YmEzMzA2NDgxMjUiLCJ0eXAiOiJKV1QifQ.eyJhcHBsaWNhdGlvbl9tZXRhZGF0YSI6e30sImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNpZCI6IjgyOTc1YjYzLTIxZGUtNDk5Mi05NWEzLTY3Y2YzYzlkZmE5NCIsImRicyI6InNhbmRib3giLCJlbWFpbCI6InRoaWJhdWRAY3J5cHRyLmNvIiwiZXhwIjoxNjYxNDUzNjE3LCJpYXQiOjE2NjE0MTc2MTcsImlwcyI6Imdvb2dsZSIsImlzcyI6Imh0dHBzOi8vc2FtbHkuaG93dG86NDQ0My90L2Jsb2NrcHVsc2UiLCJqdGkiOiJkODEyY2JlMi02MWZjLTQ4OTMtYjY5NC1jNzEwNjY5Y2VlZGYiLCJqdHQiOiJhY2Nlc3MiLCJzY2kiOiJibG9ja3B1bHNlXzZKYzNUR2F0R21zSHpleGFSUDVackUiLCJzY3AiOlsib3BlbmlkIiwiZW1haWwiLCJwcm9maWxlIl0sInN1YiI6ImQ3MWYwMzA5LTIzM2QtNGU3MC1hYjZiLWNlZWI0NDhjZmQ1YyIsInRudCI6ImJsb2NrcHVsc2UiLCJ2ZXIiOjF9.W-B5upFaes_aY9-wLv4-o7rLnJewWReUHZMgAE3uXNhgj57XE1SIJd6PzNdoEmrW5LyyJYAyPfc0FdDzQNjNbCQ-y9fEi7RtGcAatv8prqz3k9AthHci4t-nZjDr9RR5Ov-Td-R8wGIJo4qao5PfkV4yRsTj9GOdmPHvdYvhGoqwdLRUTqimX5xbx__dX3S8Tuz54LXGyTWczpwES_nAiC18BZzqZ51PLOuNLsGGXSTHn9QswycTgTlJPS-VxDeyewUEyV4yrICso88JW45h40pICTQBkWqQpcHQD3SzovsUr5Af7NPX8e-DlXtnkhf2irII6VXpxgh2rCK4mJMaM38QpM-pg_L4aoeaiQxpANnOT7BQ9-ZnM7F7ICZqa23v2a8SoS-dYagQgzRXkcJCt0oPWjbIQ9A2b_VwyZ4cbT80jDwUGYIh3qH11H9DDy5xgZBWEmcVaEn2SL2BROJGbufOmCe9LXAQQXDcPrtTMqF2Akhv9UYhRxBtMovaZFnLtHlanWU2TrWzAvccAUFR4yOFZdR4_DghJd0GkgglZClYla_r4yriibHt5ZqvkHmudYWTnqLT_XaRn002O_Zk8_KPhpi63-QeqDLqvfpee1rKKaw1PCQTXN5ceQkTpqYGJLqmExD7U2MGMn1YfcZH08mimOfO563TxoaZKbp8dKI'

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
    this.debug('_handleCallback')
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
    const pkceState = this.$auth.$storage.getUniversal(this.name + PKCE_STORAGE_KEY)
    this.debug('_handleCallback', 'pkceState', pkceState)
    if (!pkceState || !pkceState.length) {
      console.info(SLUG, 'Not going forward because pkce state unknown')
      return
    }

    this.debug('_handleCallback', "callback guards excluded")

    const hash = parseQuery(this.$auth.ctx.route.hash.substr(1))
    const parsedQuery = Object.assign({}, this.$auth.ctx.route.query, hash)
    this.debug('_handleCallback', 'parsedQuery', parsedQuery)

    let token = parsedQuery[this.options.token.property]
    this.debug('_handleCallback', 'token', token)

    let refreshToken

    if (this.options.refreshToken.property) {
      refreshToken = parsedQuery[this.options.refreshToken.property]
    }
    this.debug('_handleCallback', 'refreshToken', refreshToken)

    this.$auth.$storage.setUniversal(this.name + PKCE_STORAGE_KEY, null)
    const codeVerifier = this.$auth.$storage.getUniversal(this.name + VERIFIER_STORAGE_KEY)
    this.$auth.$storage.setUniversal(this.name + VERIFIER_STORAGE_KEY, null)


    const domain = parsedQuery['organization_domain'] || this.options.domain
    const signType = 'sso'
    const authId = parsedQuery['authorization_id']
    const authCode = parsedQuery['authorization_code']
    this.debug('_handleCallback', 'authId', authId)
    this.debug('_handleCallback', 'authCode', authCode)
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
      this.debug('_handleCallback', requestData)
    const response = await this.$auth.request({
      method: 'post',
      baseURL: this.options.baseUrl,
      url: `/api/v1/tenants/${domain}/${this.options.clientId}/oauth/${signType}/client/token`,
      data: encodeQuery(requestData)

    })

    this.debug('_handleCallback', response)
    token = getProp(response.data, this.options.token.property) || token
    this.debug('_handleCallback', 'token', token)
    refreshToken =
    (getProp(
      response.data,
      this.options.refreshToken.property
      )) || refreshToken
    this.debug('_handleCallback', 'refreshToken', refreshToken)

    if(!token || !token.length) {
      return
    }

    this.token = token
    console.log(token)

    if(refreshToken && refreshToken.length) {
      this.refreshToken = refreshToken
    }
    this.debug('_handleCallback', 'watchLoggedIn', this.$auth.options.watchLoggedIn)
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
    this.debug('fetchUser')
    // this.debug('fetchUser', 'check valid', this.check().valid)
    // if (!this.check().valid) {
    //   return
    // }

    // if (!this.options.endpoints.userInfo) {
    //   this.$auth.setUser({})
    //   return
    // }
    const url = this.userInfoUrl()
    this.debug('fetchUser', 'url', url)
    this.debug('fetchUser', 'this.token', this.token)

    const response = await this.$auth.request({
      method: 'get',
      baseURL: this.options.baseUrl,
      url: url.replace(this.options.baseUrl, ''),
      headers: {
        'Authorization': `Bearer ${TEMP_TOKEN}`
      }
    })

    this.debug('fetchUser', 'response', response)
    this.debug('fetchUser', 'response.data', response.data)
    this.debug('fetchUser', 'user value', this.options.user.property)
    this.debug('fetchUser', 'user value', getProp(response.data, this.options.user.property))

    this.$auth.setUser(getProp(response.data, this.options.user.property))
  }

  // HELPERS

    check(checkStatus = false) {
    const response = {
      valid: false,
      tokenExpired: false,
      refreshTokenExpired: false,
      isRefreshable: true
    }
    this.debug('check', checkStatus, response)

    // Sync tokens
    // const token = this.token.sync()
    // this.debug('check', 'token', token)
    // this.refreshToken.sync()
    this.debug('check', '1')

    // Token is required but not available
    if (!this.token) {
      this.debug('check', '2')
      return response
    }
    this.debug('check', '3')

    // Check status wasn't enabled, let it pass
    if (!checkStatus) {
      this.debug('check', '$')
      response.valid = true
      return response
    }
    this.debug('check', '5')

    // Get status
    const tokenStatus = this.token.status()
    const refreshTokenStatus = this.refreshToken.status()

    // Refresh token has expired. There is no way to refresh. Force reset.
    if (refreshTokenStatus.expired()) {
      response.refreshTokenExpired = true
      return response
    }

    // Token has expired, Force reset.
    if (tokenStatus.expired()) {
      response.tokenExpired = true
      return response
    }

    response.valid = true
    return response
  }

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

  userInfoUrl(tenant_domain = 'blockpulse') {
    this.debug('userInfoUrl', 'tenant_domain', tenant_domain)
    const userInfoBaseUrl =  [this.options.baseUrl, 't', tenant_domain, 'userinfo'].join('/')
    return userInfoBaseUrl + '?' + encodeQuery({client_id: this.options.clientId})
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
  user: {
    property: false
  }
}
