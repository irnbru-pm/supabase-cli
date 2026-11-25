import { readSession, writeSession } from "./irnbru.ts";
import {
  Config,
  ConfigProvider,
  Duration,
  Effect,
  FileSystem,
  Layer,
  Option,
  Path,
  Predicate,
  Redacted,
  Result,
} from "effect";
import type { PlatformError } from "effect/PlatformError";

import { RuntimeInfo } from "../shared/runtime/runtime-info.service.ts";
import { normalizeKeyringToken } from "../shared/auth/keyring-token.ts";
import { DebugLogger, type DebugLoggerShape } from "../shared/output/debug-logger.service.ts";
import { CommandSettings } from "../config/command-settings.service.ts";
import { ACCESS_TOKEN_PATTERN, validateAccessToken } from "./access-token.ts";
import { CommandCredentials } from "./command-credentials.service.ts";
import { CredentialDeleteError, DeleteTokenError, NotLoggedInError } from "./errors.ts";

const KEYRING_SERVICE = "Supabase CLI";
const LEGACY_KEYRING_ACCOUNT = "access-token";
const WSL_OSRELEASE_PATH = "/proc/sys/kernel/osrelease";

const NOT_LOGGED_IN_MESSAGE = "You were not logged in, nothing to do.";

type KeyringModule = typeof import("@napi-rs/keyring");
type KeyringEntry = InstanceType<KeyringModule["Entry"]>;
type RuntimePlatform = NodeJS.Platform;

const detectWsl = (fs: FileSystem.FileSystem): Effect.Effect<boolean> =>
  Effect.gen(function* () {
    const exists = yield* fs.exists(WSL_OSRELEASE_PATH).pipe(Effect.orElseSucceed(() => false));
    if (!exists) return false;
    const content = yield* fs
      .readFileString(WSL_OSRELEASE_PATH)
      .pipe(Effect.orElseSucceed(() => ""));
    return content.includes("WSL") || content.includes("Microsoft");
  });

const tryKeyringRead = (
  module: KeyringModule,
  account: string,
  platform: RuntimePlatform,
): Effect.Effect<Option.Option<string>> =>
  Effect.try({
    try: () => {
      const entry = new module.Entry(KEYRING_SERVICE, account);
      const value = readEntryPassword(entry);
      if (value && value.length > 0) return Option.some(normalizeKeyringToken(value));

      if (platform === "win32") {
        const windowsValue = readWindowsTarget(module, account);
        if (windowsValue && windowsValue.length > 0) {
          return Option.some(normalizeKeyringToken(windowsValue));
        }
      }

      return Option.none<string>();
    },
    catch: () => Option.none<string>(),
  }).pipe(Effect.orElseSucceed(() => Option.none<string>()));

const tryKeyringWrite = (
  module: KeyringModule,
  account: string,
  token: string,
  platform: RuntimePlatform,
): Effect.Effect<boolean> =>
  Effect.try({
    try: () => {
      if (platform === "win32") {
        return writeWindowsTarget(module, account, token);
      }

      const entry = new module.Entry(KEYRING_SERVICE, account);
      entry.setPassword(token);
      return true;
    },
    catch: () => false,
  }).pipe(Effect.orElseSucceed(() => false));

const tryKeyringDelete = (
  module: KeyringModule,
  account: string,
  platform: RuntimePlatform,
): Effect.Effect<boolean> =>
  Effect.try({
    try: () => {
      let deleted = false;

      const entry = new module.Entry(KEYRING_SERVICE, account);
      const value = readEntryPassword(entry);
      if (value) {
        entry.deleteCredential();
        deleted = true;
      }

      if (platform === "win32" && probeWindowsTarget(module, account) !== "absent") {
        deleted = deleteWindowsTarget(module, account) || deleted;
      }

      return deleted;
    },
    catch: () => false,
  }).pipe(Effect.orElseSucceed(() => false));

function readEntryPassword(entry: KeyringEntry): string | null {
  try {
    return entry.getPassword();
  } catch {
    return null;
  }
}

function windowsCredentialTarget(account: string): string {
  return `${KEYRING_SERVICE}:${account}`;
}

function readWindowsTarget(module: KeyringModule, account: string): string | null {
  try {
    const credentials = module.findCredentials(KEYRING_SERVICE, windowsCredentialTarget(account));
    const credential = credentials.find((item) => item.account === account);
    return credential ? normalizeWindowsPassword(credential.password) : null;
  } catch {
    return null;
  }
}

// `Entry.withTarget` is avoided as a probe since its constructor writes an empty placeholder. A
// `findCredentials` throw is ambiguous, so it's reported as `"unknown"`, never assumed present.
type WindowsTargetProbe = "present" | "absent" | "unknown";

function probeWindowsTarget(module: KeyringModule, account: string): WindowsTargetProbe {
  try {
    const credentials = module.findCredentials(KEYRING_SERVICE, windowsCredentialTarget(account));
    // An empty password is an orphaned placeholder, not a real credential.
    const credential = credentials.find(
      (item) => item.account === account && item.password.length > 0,
    );
    return credential ? "present" : "absent";
  } catch {
    return "unknown";
  }
}

// Constructing `withTarget` always leaves something at that target — the real
// credential, or the placeholder — so a delete that follows is never a
// legitimate "nothing to delete": any non-success is surfaced.
const deleteProbedWindowsTarget = <E>(
  module: KeyringModule,
  account: string,
  onFailure: (cause: unknown) => E,
): Effect.Effect<boolean, E> =>
  Effect.gen(function* () {
    const result = yield* Effect.try(() =>
      module.Entry.withTarget(
        windowsCredentialTarget(account),
        KEYRING_SERVICE,
        account,
      ).deleteCredential(),
    ).pipe(Effect.result);
    if (Result.isSuccess(result) && result.success) return true;
    const cause = Result.isFailure(result) ? result.failure : "credential was not removed";
    return yield* Effect.fail(onFailure(cause));
  });

function normalizeWindowsPassword(value: string): string {
  const direct = normalizeKeyringToken(value);
  if (ACCESS_TOKEN_PATTERN.test(direct)) return direct;

  // Legacy Windows CredentialBlob values are raw UTF-8 bytes, which the keyring search API
  // can surface packed into UTF-16 code units; unpack each back into the original byte sequence.
  const bytes: number[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    bytes.push(code & 0xff);
    const high = (code >> 8) & 0xff;
    if (high !== 0) bytes.push(high);
  }
  return Buffer.from(bytes).toString("utf8");
}

function writeWindowsTarget(module: KeyringModule, account: string, token: string): boolean {
  try {
    const entry = module.Entry.withTarget(
      windowsCredentialTarget(account),
      KEYRING_SERVICE,
      account,
    );
    entry.setSecret(Buffer.from(token, "utf8"));
    return true;
  } catch {
    return false;
  }
}

function deleteWindowsTarget(module: KeyringModule, account: string): boolean {
  try {
    const entry = module.Entry.withTarget(
      windowsCredentialTarget(account),
      KEYRING_SERVICE,
      account,
    );
    return entry.deleteCredential();
  } catch {
    return false;
  }
}
// Deletes the project database-password keyring entry, ignoring "nothing to delete" and
// surfacing only a real failure. Each entry is probed first, since deleting an absent macOS
// entry blocks on a Keychain prompt; on Windows a separate `withTarget` entry is also probed.
const deleteKeyringEntryStrict = (
  module: KeyringModule,
  account: string,
  platform: RuntimePlatform,
): Effect.Effect<boolean, CredentialDeleteError> =>
  Effect.gen(function* () {
    let deleted = false;

    const plain = new module.Entry(KEYRING_SERVICE, account);
    if (readEntryPassword(plain)) {
      yield* Effect.try({
        try: () => {
          plain.deleteCredential();
        },
        catch: (cause) =>
          new CredentialDeleteError({
            message: `failed to delete project credential: ${String(cause)}`,
          }),
      });
      deleted = true;
    }

    if (platform === "win32" && probeWindowsTarget(module, account) !== "absent") {
      const removed = yield* deleteProbedWindowsTarget(
        module,
        account,
        (cause) =>
          new CredentialDeleteError({
            message: `failed to delete project credential: ${String(cause)}`,
          }),
      );
      deleted ||= removed;
    }

    return deleted;
  });

// Deletes the profile's access-token keyring entry. Returns "notFound" when nothing existed
// (not an error) so the caller can treat that as already logged out.
const deleteProfileKeyringEntry = (
  module: KeyringModule,
  account: string,
  platform: RuntimePlatform,
): Effect.Effect<"deleted" | "notFound", DeleteTokenError> =>
  Effect.gen(function* () {
    let found = false;

    const plain = new module.Entry(KEYRING_SERVICE, account);
    if (readEntryPassword(plain)) {
      yield* Effect.try({
        try: () => {
          plain.deleteCredential();
        },
        catch: (cause) =>
          new DeleteTokenError({
            message: `failed to delete access token from keyring: ${String(cause)}`,
          }),
      });
      found = true;
    }

    if (platform === "win32" && probeWindowsTarget(module, account) !== "absent") {
      const removed = yield* deleteProbedWindowsTarget(
        module,
        account,
        (cause) =>
          new DeleteTokenError({
            message: `failed to delete access token from keyring: ${String(cause)}`,
          }),
      );
      found ||= removed;
    }

    return found ? "deleted" : "notFound";
  });

// Best-effort wipe of the "Supabase CLI" keyring namespace; errors are swallowed so one stuck
// credential can't abort logout. Windows credentials are also written under a separate
// target-shaped form, invisible to the plain enumeration, so they're swept separately.
const deleteAllKeyringEntries = (
  module: KeyringModule,
  platform: RuntimePlatform,
): Effect.Effect<void> =>
  Effect.sync(() => {
    if (platform === "win32") {
      try {
        const entries = module.findCredentials(KEYRING_SERVICE, `${windowsCredentialTarget("")}*`);
        for (const { account } of entries) {
          deleteWindowsTarget(module, account);
        }
      } catch {
        // best-effort
      }
    }

    let entries: ReadonlyArray<{ account: string }>;
    try {
      entries = module.findCredentials(KEYRING_SERVICE);
    } catch {
      return;
    }
    for (const { account } of entries) {
      try {
        new module.Entry(KEYRING_SERVICE, account).deleteCredential();
      } catch {
        // best-effort per entry
      }
    }
  });

// `SUPABASE_NO_KEYRING=1` disables the OS keyring entirely; without it, unconditional keyring
// access blocks on a Keychain authorization prompt in non-interactive/CI contexts.
const loadKeyringModule = (
  fs: FileSystem.FileSystem,
  noKeyring: Option.Option<string>,
): Effect.Effect<Option.Option<KeyringModule>> =>
  Effect.gen(function* () {
    const wsl = yield* detectWsl(fs);
    return wsl || (Option.isSome(noKeyring) && noKeyring.value === "1")
      ? Option.none<KeyringModule>()
      : yield* Effect.tryPromise(() => import("@napi-rs/keyring")).pipe(Effect.option);
  });

interface KeyringToken {
  readonly value: string;
  readonly account: "profile" | "legacy";
}

// Keyring chain for a given profile account: profile key first, then the legacy `access-token`
// key. Callers must pass the already-reconciled profile name.
const lookupKeyringForAccount = (
  keyringModule: Option.Option<KeyringModule>,
  profileAccount: string,
  platform: RuntimePlatform,
): Effect.Effect<Option.Option<KeyringToken>> =>
  Effect.gen(function* () {
    if (Option.isNone(keyringModule)) return Option.none<KeyringToken>();
    const profileResult = yield* tryKeyringRead(keyringModule.value, profileAccount, platform);
    if (Option.isSome(profileResult)) {
      return Option.some({ value: profileResult.value, account: "profile" });
    }
    const legacyResult = yield* tryKeyringRead(
      keyringModule.value,
      LEGACY_KEYRING_ACCOUNT,
      platform,
    );
    return Option.map(legacyResult, (value) => ({ value, account: "legacy" }));
  });

const logKeyringSource = (
  token: Option.Option<KeyringToken>,
  profileAccount: string,
  debugLogger: DebugLoggerShape,
): Effect.Effect<Option.Option<string>> =>
  Effect.gen(function* () {
    if (Option.isNone(token)) return Option.none<string>();
    yield* debugLogger.debug(
      token.value.account === "profile"
        ? `Using access token for profile: ${profileAccount}`
        : "Using access token from credentials store...",
    );
    return Option.some(token.value.value);
  });

const readFallbackFile = (
  fs: FileSystem.FileSystem,
  fallbackPath: string,
): Effect.Effect<Option.Option<string>, PlatformError> =>
  Effect.gen(function* () {
    const exists = yield* fs.exists(fallbackPath);
    if (!exists) return Option.none<string>();
    const content = yield* fs.readFileString(fallbackPath);
    const trimmed = content.trim();
    return trimmed.length === 0 ? Option.none<string>() : Option.some(trimmed);
  });

// A saved production token may only be used with the production Management API.
function managedProfile(profile: string, apiUrl: string): string {
  if (apiUrl !== "https://api.supabase.com") throw new Error("Unsupported IrnBru credential endpoint");
  return profile;
}

export const accessTokenForProfile = Effect.fn("CommandCredentials.accessTokenForProfile")(
  function* (profile: string, apiUrl?: string) {
    const settings = yield* CommandSettings;
    if (Option.isSome(settings.accessToken)) {
      yield* validateAccessToken(Redacted.value(settings.accessToken.value), "env");
      return settings.accessToken;
    }
    const raw = yield* Effect.sync(() => readSession(managedProfile(profile, apiUrl ?? settings.apiUrl)));
    if (raw === null) return Option.none<Redacted.Redacted<string>>();
    const { token } = JSON.parse(raw);
    yield* validateAccessToken(token, "stored");
    return Option.some(Redacted.make<string>(token));
  },
);

const makeCommandCredentials = Effect.gen(function* () {
  const fs = yield* FileSystem.FileSystem;
  const runtimeInfo = yield* RuntimeInfo;
  const settings = yield* CommandSettings;
  const provider = yield* ConfigProvider.ConfigProvider;
  const noKeyring = yield* Config.option(Config.String("SUPABASE_NO_KEYRING")).parse(provider);
  const keyringModule = yield* loadKeyringModule(fs, noKeyring);
  const profile = () => managedProfile(settings.profile, settings.apiUrl);
  const read = accessTokenForProfile(settings.profile);
  const getAccessToken = yield* Effect.provideService(read, CommandSettings, settings).pipe(Effect.cached);
  return CommandCredentials.of({
    getAccessToken,
    saveAccessToken: Effect.fn("CommandCredentials.saveAccessToken")(function* (token: string) {
      yield* validateAccessToken(token);
      yield* Effect.sync(() => writeSession(profile(), JSON.stringify({ token })));
    }),
    deleteAccessToken: Effect.sync(() => writeSession(profile(), null)),
    deleteAllProjectCredentials: Effect.gen(function* () {
      if (Option.isNone(keyringModule)) return;
      yield* deleteAllKeyringEntries(keyringModule.value, runtimeInfo.platform);
    }).pipe(Effect.withSpan("CommandCredentials.deleteAllProjectCredentials")),

    deleteProjectCredential: Effect.fn("CommandCredentials.deleteProjectCredential")(function* (
      projectRef: string,
    ) {
      // WSL or no keyring module: no-op success, nothing to delete.
      if (Option.isNone(keyringModule)) return false;
      return yield* deleteKeyringEntryStrict(keyringModule.value, projectRef, runtimeInfo.platform);
    }),
  });
}).pipe(Effect.withSpan("CommandCredentials.load"));

export const commandCredentialsLayer = Layer.effect(CommandCredentials, makeCommandCredentials);
