# auth_engine

An auth state machine for Flutter + Firebase apps, kept in one place so a fix lands once.

- `AuthEngine` (`lib/src/auth_engine.dart`): the orchestrator. Every state
  transition is synchronous; async work arrives as facts keyed by uid.
- `AuthStatus`, `Session`, `Profile`, `AuthGate` (`lib/src/auth_status.dart`): the values.
- `IdentityGateway`, `ProfileGateway` (`lib/src/auth_gateways.dart`): the two seams.
- `FirebaseIdentityGateway` (`lib/src/firebase_identity_gateway.dart`): the
  Firebase side of identity. An app passes `ensureGuestDoc` (its own backend
  call) and optionally `onAnonymousSignInFailed`.
- `AuthError`, `AuthException` (`lib/src/auth_error.dart`): why a step failed. The app gives each value its words.
- `AuthService<T, U>` and `FirebaseAuthService<U>` (`lib/src/auth_service.dart`,
  `firebase_auth_service.dart`): sign-in, sign-up, linking and phone for
  e-mail, Google, Apple and SMS, native and web. An app passes its user
  documents as `AuthAccounts<U>`, plus its language, log and failure report.
- `AuthFlowsCore<U>` (`lib/src/auth_flows.dart`): the interactive flows
  (sign-in, sign-up, sign-out, linking, phone, impersonation) with the flow
  loader and the error channel. An app extends it for deleting an account.
- `AuthView` (`lib/src/auth_view.dart`): the gate the app renders, composed
  from the engine and the flows.
- `PhoneLoginState`, `CredentialsStateCore` (`lib/src/`): the form states.
- `package:auth_engine/testing.dart`: `FakeIdentity`, `FakeProfiles`, `pump`.

The profile gateway stays in each app: it projects that app's user document
onto `Profile`.

## Use

```yaml
dependencies:
  auth_engine:
    git:
      url: https://github.com/<owner>/auth_engine.git
      ref: v0.4.0
```

A fix here reaches an app when that app raises `ref`.

## Check

```bash
flutter pub get
flutter analyze
flutter test
```
