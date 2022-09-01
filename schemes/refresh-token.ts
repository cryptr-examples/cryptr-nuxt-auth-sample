import jwtDecode from 'jwt-decode'
import type { JwtPayload } from 'jwt-decode'
import { addTokenPrefix } from './utils'
import { RefreshableScheme } from '@nuxtjs/auth-next'
import { TokenStatus } from './token-status'

export class RefreshToken {
  public scheme: RefreshableScheme
  public $storage: Storage

  constructor(scheme: RefreshableScheme, storage: Storage) {
    this.scheme = scheme
    this.$storage = storage
  }

  get(): string | boolean {
    const _key = this.scheme.options.refreshToken.prefix + this.scheme.name

    return this.$storage.getUniversal(_key) as string | boolean
  }

  set(tokenValue: string | boolean): string | boolean {
    const refreshToken = addTokenPrefix(
      tokenValue,
      this.scheme.options.refreshToken.type
    )

    this._setToken(refreshToken)

    return refreshToken
  }

  setExpiration(expiration: number | false) {
    const _key = this.scheme.options.refreshToken.expirationPrefix + this.scheme.name
    return this.$storage.setUniversal(_key, expiration) as number | false
  }

  private _getExpiration(): number | false {
    const _key = this.scheme.options.refreshToken.expirationPrefix + this.scheme.name
    return this.$storage.getUniversal(_key) as number | false
  }

  private _syncExpiration(): number | false {
    const _key = this.scheme.options.refreshToken.expirationPrefix + this.scheme.name
    return this.$storage.syncUniversal(_key) as number | false
  }

  sync(): string | boolean {
    const refreshToken = this._syncToken()
    this._syncExpiration()

    return refreshToken
  }

  reset(): void {
    this._setToken(false)
    this.setExpiration(false)
  }

  status(): TokenStatus {
    return new TokenStatus(this.get(), this._currentExpiration())
  }

  private _currentExpiration(refresh = this.get()): number | false {
    console.debug('refresh_token', refresh)
    let tokenExpiration
    const _issuedAtMillis = Date.now()
    const _ttlMillis = Number(this.scheme.options.refreshToken.maxAge) * 1000
    const defaultExpiration = _ttlMillis ? _issuedAtMillis + _ttlMillis : 0

    return this._getExpiration() || defaultExpiration
  }

  private _setToken(refreshToken: string | boolean): string | boolean {
    const _key = this.scheme.options.refreshToken.prefix + this.scheme.name

    return this.$storage.setUniversal(_key, refreshToken) as string | boolean
  }

  private _syncToken(): string | boolean {
    const _key = this.scheme.options.refreshToken.prefix + this.scheme.name

    return this.$storage.syncUniversal(_key) as string | boolean
  }
}
