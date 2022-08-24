import {Oauth2Scheme} from '@nuxtjs/auth-next'
import {encodeQuery, normalizePath, getProp, urlJoin, parseQuery, randomString} from './utils'
import requrl from 'requrl'


const SLUG = "CryptrScheme"


export default class CryptrScheme {

  constructor(auth, options) {
    this.$auth = auth
    this.name = options.name
    console.debug('cryptr scheme constructor')
    // console.debug('this.name', this.name)

    this.options = Object.assign({}, DEFAULTS, options)
    // this.checkEndpoints()
    this.checkOptions()
    console.debug('options', this.options)
  }

  redirectURI() {
    const basePath = this.$auth.ctx.base || ''
    const path = normalizePath(
      basePath + '/' + this.$auth.options.redirect.callback
    ) // Don't pass in context since we want the base path
    return this.options.redirectUri || urlJoin(requrl(this.req), path)
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

    let token = parsedQuery[this.options.token.property]
    console.debug('token', token)

    let refreshToken

    if (this.options.refreshToken.property) {
      refreshToken = parsedQuery[this.options.refreshToken.property]
    }
    console.debug('refreshToken', refreshToken)

    // TODO: Fetch state and verifier from db

    const domain = 'blockpulse'
    const signType = 'sso'
    const response = await this.$auth.request({
      method: 'post',
      baseURL: this.options.baseUrl,
      url: `/api/v1/tenants/${domain}/${this.options.clientId}/oauth/${signType}/client/token`,
      data: encodeQuery({
        client_id: this.options.clientId + '',
        redirect_uri: this.redirectURI(),
        responseType: this.options.resposeType,
        audience: this.options.audience,
        grant_type: this.options.grantType,
        client_state: randomString(16),
        code_verifier: randomString(16)
      })

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
    const url = this.loginUrl(params)
    console.debug(url)
    window.location.replace(url)
  }

  gatewayRootUrl() {
    return this.options.isDedicatedDomain ? this.options.baseUrl : this.options.baseUrl + '/t/' + this.options.domain
  }

  loginUrl({data}) {
    const opts = {
      client_id: this.options.clientId,
      redirect_uri: this.redirectURI(),
      state: randomString(16),
      scope: data.scope || this.options.scope.join(' '),
      code_challenge_method: this.options.codeChallengeMethod
    }
    const rawGatewayUrl = this.gatewayRootUrl() + '?' + encodeQuery(opts)
    console.debug(data)
    return (data && data.idpIds) ? (rawGatewayUrl + 'idp_ids[]=' + data.idpIds.join('&idp_ids[]=')) : rawGatewayUrl
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

  // constructor(
  //   $auth: Auth,
  //   options: SchemePartialOptions<Oauth2SchemeOptions>,
  //   ...defaults: SchemePartialOptions<Oauth2SchemeOptions>[]
  // ) {
  //   console.debug("here")
  //   super(
  //     $auth,
  //     options,
  //     ...defaults,
  //   )
  // }
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
