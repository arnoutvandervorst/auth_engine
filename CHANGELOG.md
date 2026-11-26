# Changelog

All notable changes to this package. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the package uses [semantic versioning](https://semver.org/) (pre-1.0: a minor bump may break the API). Each version is a git tag (`vX.Y.Z`) with a GitHub release.

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

[0.3.3]: https://github.com/arnoutvandervorst/auth_engine/releases/tag/v0.3.3
[0.3.2]: https://github.com/arnoutvandervorst/auth_engine/releases/tag/v0.3.2
[0.3.1]: https://github.com/arnoutvandervorst/auth_engine/commits/v0.3.2
[0.3.0]: https://github.com/arnoutvandervorst/auth_engine/releases/tag/v0.3.0
[0.2.0]: https://github.com/arnoutvandervorst/auth_engine/releases/tag/v0.2.0
[0.1.0]: https://github.com/arnoutvandervorst/auth_engine/releases/tag/v0.1.0
