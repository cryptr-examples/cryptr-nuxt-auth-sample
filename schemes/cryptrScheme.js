import { Oauth2Scheme } from '@nuxtjs/auth-next'
import {encodeQuery, generateRandomString, normalizePath, getProp, urlJoin, parseQuery, randomString} from './utils'
import requrl from 'requrl'


const SLUG = "CryptrScheme"
const PKCE_STORAGE_KEY = ".pkce_state"
const VERIFIER_STORAGE_KEY = ".pkce_code_verifier"

export default class CryptrScheme {

  constructor(auth, options) {
    this.$auth = auth
    this.name = options.name
    console.debug('cryptr scheme constructor')
    // console.debug('this.name', this.name)

    this.options = Object.assign({}, DEFAULTS, options)
    // this.checkEndpoints()
    this.checkOptions()
    this.token = null
    this.refreshToken = null
    console.debug('options', this.options)
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

  // checkEndpoints() {
  //   console.debug('checkEndpoints', this.options.endpoints)
  //   if(this.options.endpoints !== undefined) {
  //     return
  //   }
  //   console.debug('endpoints must be configured')
  //   throw new Error(`${SLUG} endpoints must be configured`)
  // }

  async mounted() {
    console.debug("mounted")
    const redirected = await this._handleCallback()
    console.debug("redirected", redirected)
    if(!redirected) {
      return this.$auth.fetchUserOnce()
    }
  }


  async _handleCallback() {
    console.debug('handleCallback')
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
    console.debug("callback guard excluded")

    const hash = parseQuery(this.$auth.ctx.route.hash.substr(1))
    const parsedQuery = Object.assign({}, this.$auth.ctx.route.query, hash)
    console.debug('parsedQuery', parsedQuery)
    console.debug('parsedQuery', Object.keys(parsedQuery))

    let token = parsedQuery[this.options.token.property]
    console.debug('token', token)

    let refreshToken

    if (this.options.refreshToken.property) {
      refreshToken = parsedQuery[this.options.refreshToken.property]
    }
    console.debug('refreshToken', refreshToken)

    // TODO: Fetch state and verifier from db
    const state = this.$auth.$storage.getUniversal(this.name + '.state')
    this.$auth.$storage.setUniversal(this.name + '.state', null)
    const pkceState = this.$auth.$storage.getUniversal(this.name + PKCE_STORAGE_KEY)
    this.$auth.$storage.setUniversal(this.name + PKCE_STORAGE_KEY, null)
    const codeVerifier = this.$auth.$storage.getUniversal(this.name + VERIFIER_STORAGE_KEY)
    this.$auth.$storage.setUniversal(this.name + VERIFIER_STORAGE_KEY, null)


    const domain = parsedQuery['organization_domain'] || this.options.domain
    const signType = 'sso'
    const authId = parsedQuery['authorization_id']
    const authCode = parsedQuery['authorization_code']
    console.debug('authId', authId)
    console.debug('authCode', authCode)
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
      console.debug(requestData)
    const response = await this.$auth.request({
      method: 'post',
      baseURL: this.options.baseUrl,
      url: `/api/v1/tenants/${domain}/${this.options.clientId}/oauth/${signType}/client/token`,
      data: encodeQuery(requestData)

    })

    console.debug(response)
    token = getProp(response.data, this.options.token.property) || token
    console.debug('token', token)
    refreshToken =
    (getProp(
      response.data,
      this.options.refreshToken.property
      )) || refreshToken
    console.debug('refreshToken', refreshToken)
    console.debug('1')

    if(!token || !token.length) {
      return
    }
    console.debug('2')
    console.debug('this.token')

    this.token = token
    console.debug('3')

    if(refreshToken && refreshToken.length) {
      this.refreshToken = refreshToken
    }
    console.debug('4')
    console.debug('watchLoggedIn', this.$auth.options.watchLoggedIn)
    if(this.$auth.options.watchLoggedIn) {
      this.$auth.redirect('home', true)
      return true
    }

    return Promise.resolve();
  }

  async login(params) {
    console.debug('login')
    console.debug('params', params)
    if(params) {
      const { data } = params
      console.debug(data)
    }
    console.debug('options', this.options)
    console.debug('endpoints', this.options.endpoints)
    await this.$auth.reset();
    const url = await this.loginUrl(params)
    console.debug(url)
    window.location.replace(url)
  }

  async logout(){
    console.debug('logout', this)
    return this.$auth.reset()
  }

  async reset() {
    console.debug('reset')
    return Promise.resolve()
  }

  async refreshToken() {
    console.debug('refreshToken')
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
    this.$auth.$storage.setUniversal(this.name + '.state', opts.state)
    const rawGatewayUrl = this.gatewayRootUrl() + '?' + encodeQuery(opts)
    console.debug(data)
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
