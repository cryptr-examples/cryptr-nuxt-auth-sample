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

  sync(): string | boolean {
    return this._syncToken()
  }

  reset(): void {
    this._setToken(false)
  }

  status(): TokenStatus {
    return new TokenStatus(this.get(), this._currentExpiration())
  }

  private _currentExpiration(refresh = this.get()) {
    let tokenExpiration
    const _issuedAtMillis = Date.now()
    const _ttlMillis = Number(this.scheme.options.refreshToken.maxAge) * 1000
    const defaultExpiration = _ttlMillis ? _issuedAtMillis + _ttlMillis : 0
    const tokenPaylod = jwtDecode<JwtPayload>(refresh + '')
    tokenExpiration = tokenPaylod.exp ? tokenPaylod.exp * 1000 : defaultExpiration
    return tokenExpiration
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
