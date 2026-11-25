import 'package:signals_flutter/signals_flutter.dart';
import 'package:auth_engine/src/auth_error.dart';
import 'package:auth_engine/src/auth_status.dart' as engine;

/// The consumer-facing auth surface: the engine's gate COMPOSED with the two
/// facts only the flows know — the flow loader and the legacy-fidelity error.
///
//* This is what replaces the legacy `AuthState` variants. The engine's gate
//* answers for the session; the flows' loader forces `loading` from a
//* state-setting flow's first synchronous moment (so settle-waits can never
//* observe a stale state), and a recorded flow error forces `failed` at full
//* fidelity. Every derived answer below reads the COMPOSED gate, which is
//* what keeps the legacy semantics: during a sign-in flow you are nobody,
//* navigable nowhere, exactly as `AuthStateAuthenticating` meant.
//*
//* The derivations live on [AuthView] so they are unit-testable against
//* plain signals; an app holds one global instance and forwards the names
//* its callers read (`authGate`, `authViewerId`, …) to it.
class AuthView {
  final ReadonlySignal<engine.AuthStatus> _status;
  final ReadonlySignal<int> _flowLoader;
  final ReadonlySignal<AuthError?> _lastError;

  late final Computed<engine.AuthGate> gate;
  late final Computed<String?> viewerId;
  late final Computed<bool> isAuthenticated;
  late final Computed<bool> canNavigate;
  late final Computed<AuthError> displayError;
  late final Computed<String?> unverifiedEmail;
  late final Computed<bool> needsEmailVerification;
  late final Computed<bool> isImpersonating;

  AuthView({required this._status, required this._flowLoader, required this._lastError}) {
    /// What the app should render, all inputs considered.
    gate = computed(() {
      if (_flowLoader.value > 0) return engine.AuthGate.loading;
      if (_lastError.value != null) return engine.AuthGate.failed;
      return _status.value.gate;
    }, options: ComputedOptions(name: 'AuthView.gate'));

    /// Whose content the app is showing, or null when there is nothing to show.
    ///
    //* The legacy `currentUserId`: null while loading or failed, the session
    //* uid otherwise — including anonymous sessions and impersonated targets.
    viewerId = computed(() {
      return switch (gate.value) {
        engine.AuthGate.loading || engine.AuthGate.failed => null,
        _ => _status.value.session.uid,
      };
    }, options: ComputedOptions(name: 'AuthView.viewerId'));

    /// Whether a session exists that feature streams may key on.
    ///
    //* Broader than [canNavigate] on purpose, exactly as the legacy computed
    //* was: a disabled account still HAS a session — its streams resolve, it
    //* just cannot go anywhere.
    isAuthenticated = computed(() {
      return switch (gate.value) {
        engine.AuthGate.ready ||
        engine.AuthGate.anonymous ||
        engine.AuthGate.onboarding ||
        engine.AuthGate.disabled ||
        engine.AuthGate.expired => true,
        _ => false,
      };
    }, options: ComputedOptions(name: 'AuthView.isAuthenticated'));

    /// Whether the user may move around the app freely. Excludes the states
    /// that must be parked on `/` (disabled, expired, failed, loading).
    canNavigate = computed(() {
      return switch (gate.value) {
        engine.AuthGate.ready || engine.AuthGate.anonymous || engine.AuthGate.onboarding => true,
        _ => false,
      };
    }, options: ComputedOptions(name: 'AuthView.canNavigate'));

    /// The error to render when [gate] is failed. Prefers the flows' channel
    /// (full legacy fidelity); the engine's coarse issue speaks only for
    /// failures the flows never saw (anonymous sign-in, profile load,
    /// unparseable status).
    displayError = computed(() {
      final flowError = _lastError.value;
      if (flowError != null) return flowError;

      return switch (_status.value.issue) {
        engine.AuthIssue.cancelled => AuthError.cancel,
        engine.AuthIssue.badCredentials => AuthError.wrongPassword,
        engine.AuthIssue.emailTaken => AuthError.emailAlreadyInUse,
        _ => AuthError.unknown,
      };
    }, options: ComputedOptions(name: 'AuthView.displayError'));

    /// The unverified email to nudge about, when known.
    unverifiedEmail = computed(() {
      final session = _status.value.session;
      return session is engine.AccountSession ? session.email : null;
    }, options: ComputedOptions(name: 'AuthView.unverifiedEmail'));

    /// Whether to show the verify-your-email banner above the deck.
    needsEmailVerification = computed(() {
      return _status.value.needsEmailVerification;
    }, options: ComputedOptions(name: 'AuthView.needsEmailVerification'));

    /// Whether this session was minted for support impersonation.
    isImpersonating = computed(() {
      return _status.value.isImpersonating;
    }, options: ComputedOptions(name: 'AuthView.isImpersonating'));
  }

  void dispose() {
    isImpersonating.dispose();
    needsEmailVerification.dispose();
    unverifiedEmail.dispose();
    displayError.dispose();
    canNavigate.dispose();
    isAuthenticated.dispose();
    viewerId.dispose();
    gate.dispose();
  }
}
