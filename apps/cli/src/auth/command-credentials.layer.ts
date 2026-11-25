import { readSession, writeSession } from "./irnbru.ts";
import {
  Config,
  ConfigProvider,
  Duration,
  Effect,
  FileSystem,
  Layer,
  Option,
  Redacted,
  Result,
} from "effect";


import { RuntimeInfo } from "../shared/runtime/runtime-info.service.ts";
import { CommandSettings } from "../config/command-settings.service.ts";
import { validateAccessToken } from "./access-token.ts";
import { CommandCredentials } from "./command-credentials.service.ts";
import { CredentialDeleteError } from "./errors.ts";

const KEYRING_SERVICE = "Supabase CLI";
const WSL_OSRELEASE_PATH = "/proc/sys/kernel/osrelease";


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
  const [getAccessToken, invalidate] = yield* Effect.cachedInvalidateWithTTL(
    Effect.provideService(read, CommandSettings, settings), Duration.infinity,
  );
  return CommandCredentials.of({
    getAccessToken,
    saveAccessToken: Effect.fn("CommandCredentials.saveAccessToken")(function* (token: string) {
      yield* validateAccessToken(token);
      yield* Effect.sync(() => writeSession(profile(), JSON.stringify({ token })));
      yield* invalidate;
    }),
    deleteAccessToken: Effect.sync(() => writeSession(profile(), null)).pipe(Effect.tap(() => invalidate)),
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
