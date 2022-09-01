import { ExpiredAuthSessionError, Oauth2Scheme } from '@nuxtjs/auth-next'
import {encodeQuery, generateRandomString, normalizePath, getProp, urlJoin, parseQuery, randomString} from './utils'
import jwtDecode from 'jwt-decode'
import requrl from 'requrl'
import { RefreshToken } from './refresh-token'
import { RefreshController } from './refresh-controller'
import { RequestHandler } from './request-handler'
import { Token } from './token'


const SLUG = "CryptrScheme"
const PKCE_STORAGE_KEY = ".pkce_state"
const VERIFIER_STORAGE_KEY = ".pkce_code_verifier"
const AUTH_STATE_KEY = ".state"
const LOGIN_TYPE_KEY = ".login_type"
const DEFAULT_SIGN_TYPE = "signin"

export default class CryptrScheme {

  constructor(auth, options) {
    this.$auth = auth
    this.name = options.name
    this.debug('cryptr scheme constructor')

    this.options = Object.assign({}, DEFAULTS, options)
    this.checkOptions()
    this.token = new Token(this, this.$auth.$storage)
    this.refreshToken = new RefreshToken(this, this.$auth.$storage)
    // this.debug('options', this.options)

    // Initialize Refresh Controller
    this.refreshController = new RefreshController(this)

    // Initialize Request Handler
    this.requestHandler = new RequestHandler(this, this.$auth.ctx.$axios)
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
    const { tokenExpired, refreshTokenExpired } = this.check(true)
    // Force reset if refresh token has expired
    // Or if `autoLogout` is enabled and token has expired
    if (refreshTokenExpired || (tokenExpired && this.options.autoLogout)) {
      this.$auth.reset()
    }
    const redirected = await this._handleCallback()
    this.debug('mounted', 'redirected', redirected)
    // if(redirected === false) {
      return this.$auth.fetchUserOnce()
    // }
  }


  async _handleCallback() {
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
    if (!pkceState || !pkceState.length) {
      console.info(SLUG, 'Not going forward because pkce state unknown')
      return
    }

    this.debug('_handleCallback', "callback guards excluded")

    const hash = parseQuery(this.$auth.ctx.route.hash.substr(1))
    const parsedQuery = Object.assign({}, this.$auth.ctx.route.query, hash)
    // this.debug('_handleCallback', 'parsedQuery', parsedQuery)

    let token = parsedQuery[this.options.token.property]
    // this.debug('_handleCallback', 'token', token)

    let refreshToken

    if (this.options.refreshToken.property) {
      refreshToken = parsedQuery[this.options.refreshToken.property]
    }
    // this.debug('_handleCallback', 'refreshToken', refreshToken)

    this.$auth.$storage.setUniversal(this.name + PKCE_STORAGE_KEY, null)
    const codeVerifier = this.$auth.$storage.getUniversal(this.name + VERIFIER_STORAGE_KEY)
    this.$auth.$storage.setUniversal(this.name + VERIFIER_STORAGE_KEY, null)


    const domain = parsedQuery['organization_domain'] || this.options.domain
    const signType = this.$auth.$storage.getUniversal(this.name + LOGIN_TYPE_KEY) || DEFAULT_SIGN_TYPE
    const authId = parsedQuery['authorization_id']
    const authCode = parsedQuery['authorization_code']
    const requestData = {
        authorization_id: authId,
        code: authCode,
        client_id: this.options.clientId + '',
        redirect_uri: this.redirectURI(),
        responseType: this.options.resposeType,
        audience: this.options.audience,
        grant_type: this.options.grantType,
        client_state: pkceState,
        code_verifier: codeVerifier,
        nonce: randomString(10),
      }
    const response = await this.$auth.request({
      method: 'post',
      baseURL: this.options.baseUrl,
      url: `/api/v1/tenants/${domain}/${this.options.clientId}/${pkceState}/oauth/${signType}/client/${authId}/token`,
      data: encodeQuery(requestData)

    })

    this.$auth.$storage.setUniversal(this.name + LOGIN_TYPE_KEY, null)

    response && response.data && this.debug('_handleCallback', 'token response', response.data)
    token = getProp(response.data, this.options.token.property) || token
    refreshToken =
    (getProp(
      response.data,
      this.options.refreshToken.property
      )) || refreshToken

    if(!token || !token.length) {
      console.warn('no token found')
      return
    }

    const idToken = getProp(response.data, 'id_token')

    this.debug('_handelCallback', this.token)
    this.token.set(token)

    // this.debug('_handelCallback', this.refreshToken)
    if(refreshToken && refreshToken.length) {
      this.refreshToken.set(refreshToken)
    }

    const refreshExpiration = getProp(response.data, "refresh_token_expires_at")
    if(refreshExpiration) {
      const expirationInt = new Date(refreshExpiration).getTime()
      this.refreshToken.setExpiration(expirationInt)
    }
    if(idToken) {
      this.debug('handleCallback', 'set user Id Token', idToken)
      const idTokenPayload = jwtDecode(idToken + '')
      this.$auth.setUser(idTokenPayload)
      return idTokenPayload != {};
    }
    if(this.$auth.options.watchLoggedIn) {
      this.$auth.redirect('home', true)
      return true
    }

    return false;
  }

  async login(params) {
    this.debug('login')
    await this.$auth.reset();
    const type = params.attrs && params.attrs.type ? params.attrs.type : 'signin'
    this.$auth.$storage.setUniversal(this.name + LOGIN_TYPE_KEY, type)
    const url = await this.loginUrl(type, params)
    console.debug(url)
    window.location.replace(url)
  }

  revokeTokenPath(refresh = this.refreshToken.get()) {
    this.debug('revokeTokenPath', 'refresh', refresh)
    const domain = refresh && refresh.length ? refresh.split('.')[0] : this.options.domain
    return [this.options.baseUrl, 'api/v1/tenants', domain, this.options.clientId, 'oauth/token/revoke'].join('/')
  }

  async logout(){
    this.debug('logout', this)
    const refresh = this.refreshToken.get()
    const path = this.revokeTokenPath(refresh)
    this.debug('logout', 'path', path)
    const revokePayload = {
      token: refresh,
      token_type_hint: 'refresh_token'
    }
    this.debug('logout', 'revokePayload', revokePayload)
    const response = await this.$auth.request({
      method: 'post',
      baseURL: this.options.baseUrl,
      url: path,
      data: revokePayload

    })
    this.debug('logout', 'response', response)
    const revokedAt = getProp(response.data, 'revoked_at')
    if(revokedAt && revokedAt.length) {
      this.debug('logout', 'token revoked')
      this.$auth.reset()
      const sloCode = getProp(response.data, 'slo_code')
      this.debug('logout', 'sloCode', sloCode)
      if(sloCode && sloCode.length) {
        const sloAfterRevokeUrl = this.sloAfterRevokeTokenUrl(sloCode, this.domainFromRefresh(refresh), this.redirectURI() || this.options.audience)
        sloAfterRevokeUrl && sloAfterRevokeUrl.length && window.location.replace(sloAfterRevokeUrl)
      }
    } else {
      console.error(SLUG, 'cannot log out')
    }
  }

  async refreshTokens() {
    this.debug("refreshTokens")
    const refreshToken = this.refreshToken.get()

    if(!refreshToken) return;

    const refreshTokenStatus = this.refreshToken.status()
    if(refreshTokenStatus.expired()) {
      this.$auth.reset()
      throw new ExpiredAuthSessionError()
    }
    const pkceState = randomString(20)
    const response = await this.$auth.request({
      method: 'post',
      url: ['api/v1/tenants', this.domainFromRefresh(refreshToken), this.options.clientId, pkceState, 'oauth/client/token'].join('/'),
      baseURL: this.options.baseUrl,
      data: encodeQuery({
        client_id: this.options.clientId,
        grant_type: 'refresh_token',
        nonce: randomString(10),
        refresh_token: refreshToken,
      })
    })

    this.updateTokens(response)

    return response;
  }

  async reset() {
    this.debug('reset')
    this.$auth.setUser(false)
    this.token.reset()
    this.refreshToken.reset()
    // this.requestHandler.reset()
  }

  async fetchUser() {
    this.debug('fetchUser')
    if (!this.check().valid) {
      this.debug('fetchUser', 'stop because check not valid')
      return
    }

    // const url = this.userInfoUrl()
    // const token = this.token.get()
    // const token = TEMP_TOKEN
    this.refreshTokens()

    // const userParams = {
    //   method: 'get',
    //   baseURL: this.options.baseUrl,
    //   url: url.replace(this.options.baseUrl, ''),
    //   headers: {
    //     'Authorization': `Bearer ${token}`
    //   }
    // }
    // try {
    //   const response = await this.$auth.request(userParams)
    //   this.debug('fetchUser', 'response')
    //   console.debug(response.data)
    //   this.$auth.setUser(getProp(response.data, this.options.user.property))

    // } catch (error) {
    //   this.debug('fetchUser', 'error', error)
    //   console.trace(error)
    // }
  }

  // HELPERS

  updateTokens(response) {
    const token = getProp(response.data, this.options.token.property)
    const refreshToken = getProp(
      response.data,
      this.options.refreshToken.property
    )
    const idToken = getProp(
      response.data,
      'id_token'
    )

    this.token.set(token)

    if (refreshToken) {
      this.refreshToken.set(refreshToken)
    }
    if (idToken) {
      this.$auth.setUser(jwtDecode(idToken + ''))
    }

    const refreshExpiration = getProp(response.data, "refresh_token_expires_at")
    if(refreshExpiration) {
      const expirationInt = new Date(refreshExpiration).getTime()
      console.debug(expirationInt)
      this.refreshToken.setExpiration(expirationInt)
    }
  }


  domainFromRefresh(refresh = this.refreshToken.get()) {
    return refresh && refresh.length ? refresh.split('.')[0] : this.options.domain
  }

  revokeTokenPath(refresh = this.refreshToken.get()) {
    this.debug('revokeTokenPath', 'refresh', refresh)
    const domain = this.domainFromRefresh(refresh)
    return [this.options.baseUrl, 'api/v1/tenants', domain, this.options.clientId, 'oauth/token/revoke'].join('/')
  }

  sloAfterRevokeTokenUrl(
    sloCode,
    domain,
    targetUrl,
  ){
    const sloParams = {
      slo_code: sloCode,
      target_url: targetUrl,
    }
    this.debug('slo after revoke', 'will  redirect to', targetUrl)
    return [this.options.baseUrl, 'api/v1/tenants', domain, this.options.clientId, 'oauth/token/slo-after-revoke-token'].join('/') + '?' + encodeQuery(sloParams)
  }

    check(checkStatus = false) {
    const response = {
      valid: false,
      tokenExpired: false,
      refreshTokenExpired: false,
      isRefreshable: true
    }

    // Sync tokens
    const token = this.token.sync()
    this.refreshToken.sync()

    // Token is required but not available
    if (!token) {
      this.debug('check', 'no token', response)
      return response
    }

    // Check status wasn't enabled, let it pass
    if (!checkStatus) {
      response.valid = true
      this.debug('check', 'no check required', response)
      console.debug(response)
      return response
    }

    // Get status
    const tokenStatus = this.token.status()
    const refreshTokenStatus = this.refreshToken.status()

    // Refresh token has expired. There is no way to refresh. Force reset.
    if (refreshTokenStatus.expired()) {
      response.refreshTokenExpired = true
      this.debug('check', 'refresh token expired', response)
      return response
    }

    // Token has expired, Force reset.
    if (tokenStatus.expired()) {
      response.tokenExpired = true
      this.debug('check', 'token expired', response)
      return response
    }

    response.valid = true
    this.debug('check', 'allchecks good', response)
    return response
  }

  debug(...args) {
    console.debug(SLUG, ...args)
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

  magicLinkRootUrl(params) {
    const magicLinkDomain = params && params.attrs && params.attrs.domain ? params.attrs.domain : this.options.domain
    return this.options.baseUrl + '/t/' +  magicLinkDomain
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

  userInfoUrl() {
    const refresh = this.refreshToken.get()
    const tenant_domain = (refresh && refresh.length) ? refresh.split('.')[0] : this.options.domain
    const userInfoBaseUrl =  [this.options.baseUrl, 't', tenant_domain, 'userinfo'].join('/')
    return userInfoBaseUrl + '?' + encodeQuery({client_id: this.options.clientId})
  }

  async loginUrl(type, params) {
    const codeVerifier = this.genAndStoreVerifier()
    const codeChallenge = await this.pkceChallengeFromVerifier(codeVerifier)
    const opts = {
      client_id: this.options.clientId,
      redirect_uri: this.redirectURI(),
      client_state: this.genAndStoreState(),
      nonce: randomString(10),
      scope: (params && params.attrs && params.attrs.scope)  ? params.attrs.scope : this.options.scope.join(' '),
      code_challenge_method: this.options.codeChallengeMethod,
      code_challenge: codeChallenge
    }
    this.$auth.$storage.setUniversal(this.name + AUTH_STATE_KEY, opts.state)
    if (type === 'sso') {
      const rawGatewayUrl = this.gatewayRootUrl() + '?' + encodeQuery(opts)
      if(params && params.attrs) {
        const { attrs } = params
        return attrs ? (rawGatewayUrl + this.buildLoginParams(attrs)) : rawGatewayUrl
      }
      return rawGatewayUrl
    } else {
      const baseMagicLinkUrl = [this.magicLinkRootUrl(params), params.attrs && params.attrs.locale ? params.attrs.locale : 'en', opts.client_state, type, 'new'].join('/')
      return baseMagicLinkUrl + '?' + encodeQuery(opts)

    }
  }

  buildLoginParams(attrs) {
    const {idpIds, ...other} = attrs
    return '&' + encodeQuery(other) + this.buildIdpParams(idpIds)
  }
  buildIdpParams(idpIds) {
    if(idpIds && idpIds.length) {
      return '&idp_ids[]=' + idpIds.join('&idp_ids[]=')
    }
    return ''
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
    // type: 'Bearer',
    name: 'Authorization',
    maxAge: 1800,
    prefix: '_token.',
    expirationPrefix: '_token_expiration.'
  },
  refreshToken: {
    property: 'refresh_token',
    maxAge: 60 * 60 * 24 * 30,
    prefix: '_refresh_token.',
    expirationPrefix: '_refresh_token_expiration.'
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
