/**
 * Session wiring: the credential store plus factories for authenticated and
 * anonymous API clients. Collaborators are injectable so command tests can
 * supply fakes without touching the network or the real credential file.
 */
import { ApiClient } from "../api/client.js";
import {
  CredentialStore,
  type Credentials,
  defaultStore,
  resolveLoginServer,
  resolvedServer,
} from "../config/credentials.js";

export interface SessionDeps {
  store?: CredentialStore;
  /** Build an `ApiClient` from a base URL and optional token (injectable). */
  clientFactory?: (baseUrl: string, token?: string | null) => ApiClient;
  env?: NodeJS.ProcessEnv;
}

export class Session {
  readonly store: CredentialStore;
  private readonly clientFactory: (baseUrl: string, token?: string | null) => ApiClient;
  private readonly env: NodeJS.ProcessEnv;

  constructor(deps: SessionDeps = {}) {
    this.store = deps.store ?? defaultStore();
    this.clientFactory =
      deps.clientFactory ??
      ((baseUrl, token) => new ApiClient({ baseUrl, token: token ?? null }));
    this.env = deps.env ?? process.env;
  }

  client(baseUrl: string, token?: string | null): ApiClient {
    return this.clientFactory(baseUrl, token ?? null);
  }

  /** A client bound to the cached server + token (throws if not logged in). */
  authedClient(): ApiClient {
    const creds = this.store.load();
    return this.client(resolvedServer(creds), creds.access_token);
  }

  load(): Credentials {
    return this.store.load();
  }

  /** Server for `login`: env override → cached → default. */
  loginServer(): string {
    return resolveLoginServer(this.env, this.store.cachedServer());
  }
}
