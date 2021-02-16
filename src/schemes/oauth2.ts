import requrl from 'requrl'
import { encodeQuery, getResponseProp, normalizePath, parseQuery, urlJoin } from '../utils'
import RefreshController from '../inc/refresh-controller'
import RequestHandler from '../inc/request-handler'
import Token from '../inc/token'
import RefreshToken from '../inc/refresh-token'
import type { SchemeCheck } from '../index'
import BaseScheme from './_scheme'

const DEFAULTS = {
  name: 'oauth2',
  accessType: null,
  redirectUri: null,
  logoutRedirectUri: null,
  clientId: null,
  audience: null,
  grantType: null,
  responseMode: null,
  acrValues: null,
  autoLogout: false,
  endpoints: {
    logout: '',
    authorization: '',
    token: '',
    userInfo: ''
  },
  scope: [],
  token: {
    property: 'access_token',
    type: 'Bearer',
    name: 'Authorization',
    maxAge: 1800,
    global: true,
    prefix: '_token.',
    expirationPrefix: '_token_expiration.'
  },
  refreshToken: {
    property: 'refresh_token',
    maxAge: 60 * 60 * 24 * 30,
    prefix: '_refresh_token.',
    expirationPrefix: '_refresh_token_expiration.'
  },
  user: {
    property: false
  },
  responseType: 'token',
  codeChallengeMethod: 'implicit'
}

export default class Oauth2Scheme extends BaseScheme<typeof DEFAULTS> {
  public req
  public token: Token
  public refreshToken: RefreshToken
  public refreshController: RefreshController
  public requestHandler: RequestHandler

  constructor ($auth, options, ...defaults) {
    super($auth, options, ...defaults, DEFAULTS)

    this.req = $auth.ctx.req

    // Initialize Token instance
    this.token = new Token(this, this.$auth.$storage)

    // Initialize Refresh Token instance
    this.refreshToken = new RefreshToken(this, this.$auth.$storage)

    // Initialize Refresh Controller
    this.refreshController = new RefreshController(this)

    // Initialize Request Handler
    this.requestHandler = new RequestHandler(this, this.$auth.ctx.$axios)
  }

  get _scope () {
    return Array.isArray(this.options.scope)
      ? this.options.scope.join(' ')
      : this.options.scope
  }

  get _redirectURI () {
    return this.options.redirectUri || urlJoin(requrl(this.req), this.$auth.options.redirect.callback)
  }

  get _logoutRedirectURI () {
    return this.options.logoutRedirectUri || urlJoin(requrl(this.req), this.$auth.options.redirect.logout)
  }

  _updateTokens (response) {
    const token = getResponseProp(response, this.options.token.property)
    const refreshToken = getResponseProp(response, this.options.refreshToken.property)

    this.token.set(token)

    if (refreshToken) {
      this.refreshToken.set(refreshToken)
    }
  }

  check (checkStatus = false): SchemeCheck {
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
      return response
    }

    // Check status wasn't enabled, let it pass
    if (!checkStatus) {
      response.valid = true
      return response
    }

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

  async mounted () {
    const { tokenExpired, refreshTokenExpired } = this.check(true)

    // Force reset if refresh token has expired
    // Or if `autoLogout` is enabled and token has expired
    if (refreshTokenExpired || (tokenExpired && this.options.autoLogout)) {
      this.$auth.reset()
    }

    // Initialize request interceptor
    this.requestHandler.initializeRequestInterceptor(this.options.endpoints.token)

    // Handle callbacks on page load
    const redirected = await this._handleCallback()

    if (!redirected) {
      return this.$auth.fetchUserOnce()
    }
  }

  reset () {
    this.$auth.setUser(false)
    this.token.reset()
    this.refreshToken.reset()
    this.requestHandler.reset()
  }

  _generateRandomString () {
    const array = new Uint32Array(28) // this is of minimum required length for servers with PKCE-enabled
    window.crypto.getRandomValues(array)
    return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('')
  }

  _sha256 (plain) {
    const encoder = new TextEncoder()
    const data = encoder.encode(plain)
    return window.crypto.subtle.digest('SHA-256', data)
  }

  _base64UrlEncode (str) {
    // Convert the ArrayBuffer to string using Uint8 array to convert to what btoa accepts.
    // btoa accepts chars only within ascii 0-255 and base64 encodes them.
    // Then convert the base64 encoded to base64url encoded
    //   (replace + with -, replace / with _, trim trailing =)
    return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }

  async _pkceChallengeFromVerifier (v, hashValue) {
    if (hashValue) {
      const hashed = await this._sha256(v)
      return this._base64UrlEncode(hashed)
    }
    return v // plain is plain - url-encoded by default
  }

  async login (_opts: { state?, params?, nonce? } = {}) {
    const url = this.options.endpoints.authorization
    window.location.replace(url)
  }

  logout () {
    let opts = {}
    if (this.options.endpoints.logout) {
      if (this.name === 'bitpod') {
        opts = {
          id_token_hint: this.$auth.$storage.getCookies()['auth.id_token'],
          post_logout_redirect_uri: this.$auth.$storage.getCookies()['auth.domain_url']
        }
      } else {
        opts = {
          client_id: this.options.clientId,
          logout_uri: this._logoutRedirectURI
        }
      }
      const url = this.options.endpoints.logout + '?' + encodeQuery(opts)
      window.location.replace(url)
    }
    return this.$auth.reset()
  }

  async fetchUser () {
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

    this.$auth.setUser(getResponseProp(response, this.options.user.property))
  }

  async _handleCallback () {
    // Handle callback only for specified route
    if (this.$auth.options.redirect && normalizePath(this.$auth.ctx.route.path) !== normalizePath(this.$auth.options.redirect.callback)) {
      return
    }
    // Callback flow is not supported in server side
    if (process.server) {
      return
    }
    const hash = parseQuery(this.$auth.ctx.route.hash.substr(1))
    const parsedQuery = Object.assign({}, this.$auth.ctx.route.query, hash)

    // Set token
    this.token.set(parsedQuery.token)
    this.$auth.$storage.setCookie('id_token', parsedQuery.id_token)
    this.$auth.$storage.setCookie('loginId', parsedQuery.loginId)
    const refreshToken = parsedQuery.refresh_token
    if (refreshToken && refreshToken.length) {
      this.refreshToken.set(refreshToken)
    }

    // Redirect to home
    this.$auth.redirect('home', true)
    return true // True means a redirect happened
  }

  async refreshTokens () {
    // Get refresh token
    const loginId = this.$auth.$storage.getCookies()['auth.loginId']
    const response = await this.$auth.request({
      method: 'get',
      url: this.options.endpoints.token + '&loginId=' + loginId
    }).catch((error) => {
      this.$auth.callOnError(error, { method: 'refreshToken' })
      return Promise.reject(error)
    })
    this._updateTokens(response)
    return response
  }
}
