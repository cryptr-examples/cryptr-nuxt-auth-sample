import { ExpiredAuthSessionError, RefreshableScheme, TokenableScheme } from '@nuxtjs/auth-next'
import type { NuxtAxiosInstance } from '@nuxtjs/axios'
import type { AxiosRequestConfig } from 'axios'

const DEFAULT_INTERCEPTOP_VALUE = -1

export class RequestHandler {
  public scheme: TokenableScheme | RefreshableScheme
  public axios: NuxtAxiosInstance
  public interceptor: number

  constructor(
    scheme: TokenableScheme | RefreshableScheme,
    axios: NuxtAxiosInstance
  ) {
    this.scheme = scheme
    this.axios = axios
    this.interceptor = DEFAULT_INTERCEPTOP_VALUE
  }

  setHeader(token: string): void {
    if (this.scheme.options.token.global) {
      // Set Authorization token for all axios requests
      this.axios.setHeader(this.scheme.options.token.name, token)
    }
  }

  clearHeader(): void {
    if (this.scheme.options.token.global) {
      // Clear Authorization token for all axios requests
      this.axios.setHeader(this.scheme.options.token.name, false)
    }
  }

  // ---------------------------------------------------------------
  initializeRequestInterceptor(refreshEndpoint?: string): void {
    this.interceptor = this.axios.interceptors.request.use(async (config) => {
      // Don't intercept refresh token requests
      if (!this._needToken(config) || config.url === refreshEndpoint) {
        return config
      }
      let isValid = false

      if (this.scheme) {
        if (this.scheme.check) {
          // Perform scheme checks.
          const { valid, tokenExpired, refreshTokenExpired, isRefreshable } =
            this.scheme.check(true)
          isValid = valid
          // Refresh token has expired. There is no way to refresh. Force reset.
          if (refreshTokenExpired && this.scheme.reset) {
            this.scheme.reset()
            throw new ExpiredAuthSessionError()
          }
          if (tokenExpired) {
            // Refresh token is not available. Force reset.
            if (!isRefreshable && this.scheme.reset) {
              this.scheme.reset()
              throw new ExpiredAuthSessionError()
            }

            // Refresh token is available. Attempt refresh.
            isValid = await (this.scheme as RefreshableScheme)
              .refreshTokens()
              .then(() => true)
              .catch(() => {
                // Tokens couldn't be refreshed. Force reset.
                if(this.scheme.reset) {
                  this.scheme.reset()
                }
                throw new ExpiredAuthSessionError()
              })
          }
        }

      }

      // Sync token
      const token = this.scheme.token.get()

      // Scheme checks were performed, but returned that is not valid.
      if (!isValid) {
        // The authorization header in the current request is expired.
        // Token was deleted right before this request
        if (!token && this._requestHasAuthorizationHeader(config)) {
          throw new ExpiredAuthSessionError()
        }

        return config
      }

      // Token is valid, let the request pass
      // Fetch updated token and add to current request
      return this._getUpdatedRequestConfig(config, token)
    })
  }

  reset(): void {
    // Eject request interceptor
    this.axios.interceptors.request.eject(this.interceptor)
    this.interceptor = DEFAULT_INTERCEPTOP_VALUE
  }

  private _needToken(config: any): boolean {
    const options = this.scheme.options
    const tokenGlobal = options.token.global
    const endpointsValues = Object.values(options.endpoints)
    return (
      tokenGlobal ||
      endpointsValues.some((endpoint: AxiosRequestConfig | string | boolean) =>
      endpoint === true ||
        (typeof endpoint === 'object'
          ? endpoint.url === config.url
          : endpoint === config.url)
      )
    )
  }

  // ---------------------------------------------------------------
  // Watch requests for token expiration
  // Refresh tokens if token has expired

  private _getUpdatedRequestConfig(config: any, token: string | boolean) {
    if (typeof token === 'string') {
      config.headers[this.scheme.options.token.name] = token
    }

    return config
  }

  private _requestHasAuthorizationHeader(config: any): boolean {
    return !!config.headers.common[this.scheme.options.token.name]
  }
}
