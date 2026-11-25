# auth_engine

The auth state machine that the apps both run, so a fix lands once.

- `AuthEngine` (`lib/src/auth_engine.dart`): the orchestrator. Every state
  transition is synchronous; async work arrives as facts keyed by uid.
- `AuthStatus`, `Session`, `Profile`, `AuthGate` (`lib/src/auth_status.dart`): the values.
- `IdentityGateway`, `ProfileGateway` (`lib/src/auth_gateways.dart`): the two seams.
- `FirebaseIdentityGateway` (`lib/src/firebase_identity_gateway.dart`): the
  Firebase side of identity. An app passes `ensureGuestDoc` (its own backend
  call) and optionally `onAnonymousSignInFailed`.
- `package:auth_engine/testing.dart`: `FakeIdentity`, `FakeProfiles`, `pump`.

The profile gateway stays in each app: it projects that app's user document
onto `Profile`.

## Use

```yaml
dependencies:
  auth_engine:
    git:
      url: https://github.com/<owner>/auth_engine.git
      ref: v0.1.0
```

A fix here reaches an app when that app raises `ref`.

## Check

```bash
flutter pub get
flutter analyze
flutter test
```
