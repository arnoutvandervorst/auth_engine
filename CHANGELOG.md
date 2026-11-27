# Changelog

All notable changes to this package. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the package uses [semantic versioning](https://semver.org/) (pre-1.0: a minor bump may break the API). Each version is a git tag (`vX.Y.Z`) with a GitHub release.

## [0.4.0] - 2026-11-27
### Fixed
- A step that fails after a provider sign-in (a document read on a bad network) no longer deletes a returning account or a guest that was just linked. What is undone follows from the provider's answer, before any document is read: a new account is removed, a linked guest gets the provider taken off, a returning account is only signed out (`FirebaseAuthService.undoFor`).
- `sendPasswordResetEmail`, `sendEmailVerification` and `refreshEmailVerificationStatus` throw `AuthException` instead of a raw `FirebaseAuthException`, so `AuthFlowsCore.sendEmailVerification` and `emailVerified` answer false / null as documented.
- A form-local sign-in that fails with something other than an `AuthException` returns `AuthError.unknown` to the form; it no longer flips the global gate to failed while the form hears success.
- A failed `GoogleSignIn.initialize()` is not kept: the next attempt initializes again.
- `startPhoneVerification`: a call that throws reports `verificationFailed(AuthError.unknown)` and leaves the global gate alone.
- `PhoneLoginState` signs in when Android verifies the number without a code, instead of staying busy.
- `CredentialsStateCore.run` writes nothing after `dispose` (a sign-in that closes the page).
- A live profile stream that ends on an error is opened again (up to three times per session), so a later change still arrives.
- Closing the provider popup or sheet (`popup-closed-by-user`, `cancelled-popup-request`, `canceled`, `web-context-canceled`) maps to `AuthError.cancel`.
- The engine starts no new work after `dispose`.
- `onLogin` / `onSignUp` fire for a sign-in that went through, not for an attempt; a failed phone link is reported once.
### Added
- `AuthService.signInWithPhoneAuthCredential` and `AuthFlowsCore.signInWithVerifiedPhone`; `startPhoneVerification` takes an optional `verificationCompleted`. An app's own `AuthService` implementation must add the method.
- `mustVerifyEmail(user)`: the one rule the session and the auth service answer from.
- `FakeProfiles.fail` in `testing.dart`.
### Changed
- The four sign-in paths (phone, Google, Apple, e-mail) share one tail. A new e-mail account now also reads its user document first, like the others.
### Removed
- `AuthFlowsCore.clearError`: it was the same as `retry`.

## [0.3.4] - 2026-11-26
### Fixed
- `PhoneLoginState` writes nothing after `dispose`: a page closed while the code was being sent or checked no longer sets `verificationId`, `resendToken`, `errorAuthError` or `isLoading` on disposed signals.

## [0.3.3] - 2026-11-25
### Changed
- App-neutral wording in the docs and comments.

## [0.3.2] - 2026-11-25
### Fixed
- `pubspec.yaml` and `README.md` restored: 0.3.1 shipped both files empty. Do not use 0.3.1.

## [0.3.1] - 2026-11-25
### Changed
- `PhoneLoginState` takes a getter for the flows.

## [0.3.0] - 2026-11-25
### Added
- The interactive flows: `AuthFlowsCore<U>`, the composed `AuthView`, `PhoneLoginState` and `CredentialsStateCore`. Analytics, logging and app-specific flows (such as deleting an account) come in from the app.

## [0.2.0] - 2026-11-25
### Added
- `AuthError`, `AuthService` and one `FirebaseAuthService`: guest unlink on a failed link, failure reports, and the web paths (popup sign-in, web phone confirmation, lazy `google_sign_in` initialize, ID token refresh before the verification reload). The app's user documents come in as `AuthAccounts<U>`.

## [0.1.0] - 2026-11-25
### Added
- The auth engine, its values and gateways, and the Firebase identity gateway.

[0.3.4]: https://github.com/arnoutvandervorst/auth_engine/releases/tag/v0.3.4
[0.3.3]: https://github.com/arnoutvandervorst/auth_engine/releases/tag/v0.3.3
[0.3.2]: https://github.com/arnoutvandervorst/auth_engine/releases/tag/v0.3.2
[0.3.1]: https://github.com/arnoutvandervorst/auth_engine/commits/v0.3.2
[0.3.0]: https://github.com/arnoutvandervorst/auth_engine/releases/tag/v0.3.0
[0.2.0]: https://github.com/arnoutvandervorst/auth_engine/releases/tag/v0.2.0
[0.1.0]: https://github.com/arnoutvandervorst/auth_engine/releases/tag/v0.1.0
