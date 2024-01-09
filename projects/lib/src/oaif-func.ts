import { HashHandler } from "angular-oauth2-oidc";
import { b64DecodeUnicode, base64UrlEncode } from "./base64-helper";
import { WebHttpUrlEncodingCodec } from "./encoder";
import { EventType, OAuthErrorEvent, OAuthSuccessEvent } from "./events";
import { TokenResponse } from "./types";

export const SILENT_TOKEN_PREFIX = 'silent_token_';
export const TOKEN_PENDING = '...Pending';

export const sortScopes = (scopes: string): string => scopes.split(' ').sort().join(' ');

interface OAIFMessage {
  id: string;
  type: string;
  queryParams: string;
}

export abstract class OAIFEvent {
  constructor(readonly type: EventType, tokenKey: string) {}
}

export class OAIFSuccessEvent extends OAIFEvent {
  constructor(type: EventType, tokenKey: string, readonly info: any = null) {
    super(type,tokenKey);
  }
}

export class OAIFInfoEvent extends OAIFEvent {
  constructor(type: EventType, tokenKey: string, readonly info: any = null) {
    super(type,tokenKey);
  }
}

export class OAIFErrorEvent extends OAIFEvent {
  constructor(
    type: EventType, tokenKey: string,
    readonly reason: object,
    readonly params: object = null
  ) {
    super(type,tokenKey);
  }
}

export interface OAIFListenerConfig {
  clientId: string;
  accessTokenEndpoint: string;
  httpClient: HttpClient;
  retrieveState: (tokenKeyWithPrefix: string) => string;
  retrievePkceVerifier: (tokenKeyWithPrefix: string) => string;
  storeAccessTokenResponse: (tokenKeyWithPrefix: string, access_token: string) => void;
  events: Observable<OAIFEvent>;
}

export interface OAIFAuthorizeConfig {
  tokenKey: string;
  redirectUri: string;
  scopes: string;
  authorizeUri: string;
  clientId: string;
  events: Observable<OAIFEvent>;
  storeNonce: (tokenKeyWithPrefix: string, nonce: string) => void;
  storeAccessToken: (tokenKeyWithPrefix: string, access_token: string) => void;
  retrieveAccessToken: (tokenKeyWithPrefix: string) => string;
  storePkceVerifier: (tokenKeyWithPrefix: string, verifier: string) => string;
  hashHandler: HashHandler;
}


function removeSilentRefreshEventListener(listener): void {
    if (listener) {
      window.removeEventListener(
        'message',
        listener
      );
    }
  }

function getCodePartsFromUrl(queryString: string): object {

    // normalize query string
    if (queryString.charAt(0) === '#') {
      queryString = queryString.substring(1);
    }

    if (queryString.charAt(0) === '?') {
      queryString = queryString.substring(1);
    }
    const data = {};
    let pair, separatorIndex, escapedKey, escapedValue, key, value;

    if (queryString === null) {
      return data;
    }

    const pairs = queryString.split('&');

    for (let i = 0; i < pairs.length; i++) {
      pair = pairs[i];
      separatorIndex = pair.indexOf('=');

      if (separatorIndex === -1) {
        escapedKey = pair;
        escapedValue = null;
      } else {
        escapedKey = pair.substr(0, separatorIndex);
        escapedValue = pair.substr(separatorIndex + 1);
      }

      key = decodeURIComponent(escapedKey);
      value = decodeURIComponent(escapedValue);

      if (key.substr(0, 1) === '/') {
        key = key.substr(1);
      }

      data[key] = value;
    }

    return data;
}

function getTokenFromCode(
  code: string, tokenKeyWithPrefix: string, config: OAIFListenerConfig, 
): Promise<object> {
  let params = new HttpParams({ encoder: new WebHttpUrlEncodingCodec() })
    .set('grant_type', 'authorization_code')
    .set('code', code)
    .set('code_verifier',config.retrievePkceVerifier(tokenKeyWithPrefix));
    //.set('redirect_uri', options.customRedirectUri || this.redirectUri);

  return fetchAndProcessToken(params,tokenKeyWithPrefix,config);
}

function fetchAndProcessToken(
  params: HttpParams, tokenKeyWithPrefix: string, config: OAIFListenerConfig
): Promise<TokenResponse> {

  let headers = new HttpHeaders().set(
    'Content-Type',
    'application/x-www-form-urlencoded'
  );

  params = params.set('client_id', config.clientId);

  return new Promise((resolve, reject) => {
    config.httpClient
      .post<TokenResponse>(config.accessTokenEndpoint, params, { headers })
      .subscribe(
        (tokenResponse) => {
          console.debug('refresh tokenResponse', tokenResponse);
          config.storeAccessTokenResponse(tokenKeyWithPrefix, tokenResponse.access_token);
          config.events.next(new OAIFSuccessEvent('token_received',tokenKeyWithPrefix));
          config.events.next(new OAIFSuccessEvent('token_refreshed',tokenKeyWithPrefix));
          resolve(tokenResponse);
        },
        (err) => {
          console.error('Error getting token', err);
          config.events.next(new OAIFErrorEvent('token_refresh_error',tokenKeyWithPrefix, err));
          reject(err);
        }
      );
  });
}

async function tryLoginCodeFlow(message: OAIFMessage,config: OAIFListenerConfig): Promise<void> {

    const parts = getCodePartsFromUrl(message.queryParams);

    const code = parts['code'];
    const state = parts['state'];

    if (parts['error']) {
      console.debug('error trying to login');
      const err = new OAIFErrorEvent('code_error', message.id,{}, parts);
      config.events.next(err);
      return Promise.reject(err);
    }

    if (config.retrieveState(message.id) !== state) {
      const event = new OAIFErrorEvent('invalid_nonce_in_state',message.id, null);
      config.events.next(event);
      return Promise.reject(event);
    }

    await getTokenFromCode(code,message.id,config);
    //this.restoreRequestedRoute();
    return Promise.resolve();
}

export function setupSilentRefreshEventListener(oldListener,config: OAIFListenerConfig): ((e: MessageEvent) => void) {
    removeSilentRefreshEventListener(oldListener);
    
    const newListener = (e: MessageEvent<OAIFMessage>) => {
        const message = e.data;
  
        if(e || e.data && e.data.type) {
          if (e.origin !== location.origin) {
            console.error('wrong origin requested silent refresh!');
          }
    
          tryLoginCodeFlow(message,config).catch((err) =>
            console.debug('tryLogin during silent refresh failed', err)
          );
        }
      };
  
      window.addEventListener(
        'message',
        newListener
      );
      return newListener;
}

function createNonce(): Promise<string> {
  return new Promise((resolve) => {
    const unreserved =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    let size = 45;
    let id = '';

    const crypto =
      typeof self === 'undefined' ? null : self.crypto || self['msCrypto'];
    if (crypto) {
      let bytes = new Uint8Array(size);
      crypto.getRandomValues(bytes);

      // Needed for IE
      if (!bytes.map) {
        (bytes as any).map = Array.prototype.map;
      }

      bytes = bytes.map((x) => unreserved.charCodeAt(x % unreserved.length));
      id = String.fromCharCode.apply(null, bytes);
    } else {
      while (0 < size--) {
        id += unreserved[(Math.random() * unreserved.length) | 0];
      }
    }

    resolve(base64UrlEncode(id));
  });
}

function createAndSaveNonce(config: OAIFAuthorizeConfig): Promise<string> {
  const that = this; // eslint-disable-line @typescript-eslint/no-this-alias
  return this.createNonce().then(function (nonce: any) {
    config.storeNonce(SILENT_TOKEN_PREFIX + config.tokenKey,nonce);
    return nonce;
  });
}

async function createChallangeVerifierPairForPKCE(config: OAIFAuthorizeConfig): Promise<
    [string, string]
  > {
    if (!this.crypto) {
      throw new Error(
        'PKCE support for code flow needs a CryptoHander. Did you import the OAuthModule using forRoot() ?'
      );
    }

    const verifier = await createNonce();
    const challengeRaw = await config.hashHandler.calcHash(verifier, 'sha-256');
    const challenge = base64UrlEncode(challengeRaw);

    return [challenge, verifier];
  }

async function createLoginUrl(
  config: OAIFAuthorizeConfig, redirectUri: string
): Promise<string> {

  const state = await createAndSaveNonce(config);

  let url =
    config.authorizeUri +
    '?' +
    'response_type=code' +
    '&client_id=' +
    encodeURIComponent(config.authorizeUri) +
    '&state=' +
    encodeURIComponent(state) +
    '&redirect_uri=' +
    encodeURIComponent(redirectUri) +
    '&scope=' +
    encodeURIComponent(config.scopes);

  const [challenge, verifier] =
    await createChallangeVerifierPairForPKCE(config);

  config.storePkceVerifier(SILENT_TOKEN_PREFIX + config.tokenKey,verifier)

  url += '&code_challenge=' + challenge;
  url += '&code_challenge_method=S256';
  url += '&nonce=' + encodeURIComponent(state);

  return url;
}

function checkExistingTokenPendingOrSetPending(config: OAIFAuthorizeConfig): boolean {
  const currentToken = config.retrieveAccessToken(SILENT_TOKEN_PREFIX + config.tokenKey);
  if(currentToken && currentToken === '...Pending') {
    return true;
  } else {
    config.storeAccessToken(SILENT_TOKEN_PREFIX + config.tokenKey,'...Pending');
    return false;
  }
}

function isTokenNotExpired(token: string) {
  return (JSON.parse(b64DecodeUnicode(token.split('.')[1])).exp * 1000)
    >
    new Date().getTime();
}

function checkExistingTokenAndNotExpired(config: OAIFAuthorizeConfig): boolean {
  const currentToken = config.retrieveAccessToken(SILENT_TOKEN_PREFIX + config.tokenKey);
  return !!currentToken && isTokenNotExpired(currentToken)
}

export function oaifToken(config: OAIFAuthorizeConfig): Promise<OAIFEvent> {

    if(checkExistingTokenAndNotExpired(config)) {
        return of(new OAIFSuccessEvent('silently_refreshed',SILENT_TOKEN_PREFIX + config.tokenKey)).toPromise();
    }

    if(!checkExistingTokenPendingOrSetPending(config)) {
      if (typeof document === 'undefined') {
        throw new Error('silent refresh is not supported on this platform');
      }

      const existingIframe = document.getElementById(
          SILENT_TOKEN_PREFIX + config.tokenKey
      );
    
      if (existingIframe) {
          document.body.removeChild(existingIframe);
      }

      const iframe = document.createElement('iframe');
      iframe.id =SILENT_TOKEN_PREFIX + config.tokenKey;

      const redirectUri = window.location.origin + "/silent-refresh-oaif.html";
      createLoginUrl(config,redirectUri).then(
        (url) => {
          iframe.setAttribute('src', url);
          iframe.style['display'] = 'none';
          document.body.appendChild(iframe);
        }
      );
    }
    

    const errors = config.events.pipe(
      filter((e) => e instanceof OAuthErrorEvent),
      first()
    );
    const success = config.events.pipe(
      filter((e) => e.type === 'token_received'),
      first()
    );
    const timeout = of(
      new OAIFErrorEvent('silent_refresh_timeout',SILENT_TOKEN_PREFIX + config.tokenKey, null)
    ).pipe(delay(10000));

    return race([errors, success, timeout])
      .pipe(
        map((e) => {
          if (e instanceof OAuthErrorEvent) {
            if (e.type !== 'silent_refresh_timeout') {
              e = new OAIFErrorEvent('silent_refresh_error',SILENT_TOKEN_PREFIX + config.tokenKey, e);
            } else {
              if(checkExistingTokenAndNotExpired(config)) {
                e = of(new OAIFSuccessEvent('silently_refreshed',SILENT_TOKEN_PREFIX + config.tokenKey)).toPromise();
              }
            }
            throw e;
          } else if (e.type === 'token_received') {
            e = new OAIFSuccessEvent('silently_refreshed',SILENT_TOKEN_PREFIX + config.tokenKey);
          }
          return e;
        })
      )
      .toPromise();
}