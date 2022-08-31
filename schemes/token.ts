import jwtDecode from 'jwt-decode'
import type { JwtPayload } from 'jwt-decode'
import { TokenStatus } from './token-status'
import { TokenableScheme } from '@nuxtjs/auth-next'
import { addTokenPrefix } from './utils'

export class Token {
  public scheme: TokenableScheme
  public $storage: Storage

  constructor(scheme: TokenableScheme, storage: Storage) {
    this.scheme = scheme
    this.$storage = storage
  }

  get(): string | boolean {
    const _key = this.scheme.options.token.prefix + this.scheme.name

    return this.$storage.getUniversal(_key) as string | boolean
  }

  set(tokenValue: string | boolean): string | boolean {
    console.debug('Token class', 'set', tokenValue)
    const token = addTokenPrefix(tokenValue, this.scheme.options.token.type)

    this._setToken(token)

    if (this.scheme.requestHandler && typeof token === 'string') {
      this.scheme.requestHandler.setHeader(token)
    }

    return token
  }

  sync(): string | boolean {
    const token = this._syncToken()

    if (this.scheme.requestHandler && typeof token === 'string') {
      this.scheme.requestHandler.setHeader(token)
    }

    return token
  }

  reset(): void {
    if (this.scheme.requestHandler) {
      this.scheme.requestHandler.clearHeader()
    }
    this._setToken(false)
  }

  status(): TokenStatus {
    return new TokenStatus(this.get(), this._currentExpiration())
  }

  private _currentExpiration(token = this.get()){
    let tokenExpiration
    const _issuedAtMillis = Date.now()
    const _ttlMillis = Number(this.scheme.options.token.maxAge) * 1000
    const defaultExpiration = _ttlMillis ?_issuedAtMillis + _ttlMillis : 0
    const tokenPaylod = jwtDecode<JwtPayload>(token + '')
    tokenExpiration = tokenPaylod.exp ? tokenPaylod.exp * 1000 : defaultExpiration
    return tokenExpiration
  }

  private _setToken(token: string | boolean): string | boolean {
    const _key = this.scheme.options.token.prefix + this.scheme.name

    return this.$storage.setUniversal(_key, token) as string | boolean
  }

  private _syncToken(): string | boolean {
    const _key = this.scheme.options.token.prefix + this.scheme.name

    return this.$storage.syncUniversal(_key) as string | boolean
  }
}
