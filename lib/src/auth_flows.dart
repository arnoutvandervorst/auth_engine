import 'package:auth_engine/src/auth_engine.dart';
import 'package:auth_engine/src/auth_error.dart';
import 'package:auth_engine/src/auth_service.dart';
import 'package:firebase_auth/firebase_auth.dart' as auth;
import 'package:flutter/foundation.dart' show protected;
import 'package:signals_flutter/signals_flutter.dart';

/// The interactive auth flows: sign-in, sign-up, sign-out, linking, phone
/// verification, impersonation. Orchestration, not state.
///
//* The engine decides what the state IS; this class runs the provider
//* choreography that changes it, and owns the two signals that choreography
//* produces: the flow loader (state-setting flows show the spinner from
//* method entry, synchronously — which is what makes settle-on-next-state
//* waits sound) and the fidelity-preserving error channel (the engine's
//* AuthIssue is deliberately coarse; the UI shows wrong-password vs
//* email-in-use). `auth_view.dart` composes both into the gate the app
//* renders. The class itself imports no app state; session-end cleanup
//* arrives as a constructor callback.
//*
//* An app extends it for what is its own: deleting an account, and the result
//* of the e-mail verification check in that app's words ([U] is its user
//* document).
class AuthFlowsCore<U> {
  final AuthEngine _engine;
  final AuthService<auth.User, U> _service;
  final Future<void> Function() _onSessionEnded;
  final void Function(String message) _log;

  /// Told the method of each interactive sign-in / sign-up that went through
  /// (`email_password`, `google`, `apple`), for the app's analytics. Never an
  /// e-mail or other PII.
  final void Function(String method)? _onLogin;
  final void Function(String method)? _onSignUp;

  /// Interactive state-setting flows in flight. While positive, the derived
  /// state is `Authenticating` — set synchronously at flow entry, so
  /// "settle on the next state" waits can never observe the previous state.
  final flowLoader = signal<int>(0, options: SignalOptions(name: 'AuthFlows.loader'));

  /// The last flow failure, at legacy fidelity. Sticky until
  /// [retry], or the next flow starts.
  final lastError = signal<AuthError?>(null, options: SignalOptions(name: 'AuthFlows.lastError'));

  /// Mints an impersonation token (target → enter; none → return ticket).
  /// Null means the endpoint refused.
  final Future<String?> Function({String? targetUserId}) _mintImpersonationToken;

  AuthFlowsCore({
    required this._engine,
    required this._service,
    required this._onSessionEnded,
    required this._mintImpersonationToken,
    required this._log,
    this._onLogin,
    this._onSignUp,
  });

  /// The engine, the service and the flow bracket, for the app's own flows.
  @protected
  AuthEngine get engine => _engine;

  @protected
  AuthService<auth.User, U> get service => _service;

  /// Runs the app's session-end cleanup (release the push target, drop drafts).
  @protected
  Future<void> sessionEnded() => _onSessionEnded();

  /// Runs [operation] as a state-setting flow: loader up from the first
  /// synchronous moment, a failure into [lastError].
  @protected
  Future<T?> flow<T>(Future<T> Function() operation) => _flow(operation);

  Future<T?> _flow<T>(Future<T> Function() operation) async {
    lastError.value = null;
    flowLoader.value++;
    try {
      return await _engine.runFlow(() async {
        try {
          return await operation();
        } on AuthException catch (e) {
          lastError.value = e.authError;
          rethrow;
        }
      });
    } finally {
      //* Dropped AFTER the engine's bracket, so the derive that follows sees
      //* the flow's outcome rather than a mid-flight snapshot.
      flowLoader.value--;
    }
  }

  /// Runs an interactive sign-in with FORM-LOCAL failure semantics, the same
  /// contract the link flows established: the [AuthError] is returned to the
  /// calling form instead of flipping the global gate, so the user stays on
  /// the page with their input intact. The engine's flow bracket is kept
  /// (the session supervisor must not interfere mid-flow), but a credential
  /// failure is caught INSIDE it — the engine never publishes an issue and
  /// neither [flowLoader] nor [lastError] move. Cancel is a silent no-op.
  /// Success returns null (after [onSuccess]); global navigation then follows
  /// from the engine's own session/profile resolution, exactly as before.
  Future<AuthError?> _localFlow(Future<void> Function() operation, {void Function()? onSuccess}) async {
    return await _engine.runFlow<AuthError?>(() async {
      try {
        await operation();
        onSuccess?.call();
        return null;
      } on AuthException catch (e) {
        return e.authError == AuthError.cancel ? null : e.authError;
      } catch (error) {
        //* Anything else (a plugin that failed to start) stays on the form
        //* too. Left to the engine it flipped the global gate to failed while
        //* the form was told the sign-in went through.
        _log('Auth flow failed: $error');
        return AuthError.unknown;
      }
    });
  }

  /// Signs in a user with email and password credentials. Failure is
  /// form-local: the error is returned, the global gate never moves.
  Future<AuthError?> signInWithEmailAndPassword({required String email, required String password}) async {
    return await _localFlow(
      () => _service.signInWithEmailAndPassword(email: email, password: password),
      onSuccess: () => _onLogin?.call('email_password'),
    );
  }

  /// Signs in anonymously. Normally the engine's supervisor does this on its
  /// own; the method exists for explicit retries.
  Future<void> signInAnonymously() async {
    await _flow(() => _service.signInAnonymously());
  }

  /// Signs in a user using their Google account.
  ///
  //* No explicit state transition on success: the engine listens to
  //* `userChanges`, which emits even for same-uid links (the guest upgrade),
  //* so the machinery that papered over `authStateChanges` staying silent is
  //* simply gone.
  Future<AuthError?> signInWithGoogle() async {
    return await _localFlow(() async {
      final user = await _service.signInWithGoogle();
      if (user == null) throw const AuthException(AuthError.cancel);
    }, onSuccess: () => _onLogin?.call('google'));
  }

  /// Signs in a user using their Apple ID.
  Future<AuthError?> signInWithApple() async {
    return await _localFlow(() async {
      final user = await _service.signInWithApple();
      if (user == null) throw const AuthException(AuthError.cancel);
    }, onSuccess: () => _onLogin?.call('apple'));
  }

  /// Starts a phone-number verification, returning the verification id via
  /// [codeSent]. Stateless on purpose — no loader, exactly as before: this
  /// runs inside onboarding, and a loader here would flash over the stepper.
  ///
  /// [verificationCompleted]: Android verified the number without a code
  /// (no [codeSent] follows then); sign in with [signInWithVerifiedPhone].
  /// Exactly one of the three callbacks ends every call.
  Future<void> startPhoneVerification({
    required String phoneNumber,
    required void Function(String verificationId, int? resendToken) codeSent,
    required void Function(AuthError error) verificationFailed,
    void Function(AbstractPhoneAuthCredential credential)? verificationCompleted,
  }) async {
    await _engine.runFlow(() async {
      try {
        await _service.verifyPhoneNumber(
          phoneNumber: phoneNumber,
          codeSent: codeSent,
          verificationCompleted: (credential) => verificationCompleted?.call(credential),
          verificationFailed: (error) => verificationFailed(_phoneAuthErrorFor(error)),
          codeAutoRetrievalTimeout: (_) {},
        );
      } catch (error) {
        //* A call that throws instead of answering: the form hears it, and the
        //* global gate stays where it is.
        _log('Phone verification failed to start: $error');
        verificationFailed(AuthError.unknown);
      }
    });
  }

  /// Signs in with the phone credential [startPhoneVerification] handed to
  /// `verificationCompleted`. Failure is form-local.
  Future<AuthError?> signInWithVerifiedPhone(AbstractPhoneAuthCredential credential) async {
    return await _localFlow(() => _service.signInWithPhoneAuthCredential(credential));
  }

  /// Signs in with a phone verification id + SMS code. Failure is form-local.
  Future<AuthError?> signInWithPhone({required String verificationId, required String smsCode}) async {
    return await _localFlow(
      () => _service.signInWithPhoneCredential(verificationId: verificationId, smsCode: smsCode),
    );
  }

  /// Maps codes returned by `verifyPhoneNumber`'s failure callback to a typed [AuthError].
  AuthError _phoneAuthErrorFor(AbstractAuthError error) {
    return switch (error.code) {
      'invalid-phone-number' => AuthError.invalidCredential,
      'too-many-requests' => AuthError.tooManyRequests,
      'invalid-verification-code' => AuthError.invalidVerificationCode,
      'credential-already-in-use' => AuthError.credentialAlreadyInUse,
      'operation-not-allowed' => AuthError.operationNotAllowed,
      _ => AuthError.unknown,
    };
  }

  /// Returns the provider IDs currently linked to the authenticated Firebase user.
  List<String> get linkedProviderIds => _service.linkedProviderIds;

  /// Links a Google account to the currently authenticated user.
  ///
  /// Returns null on success or cancel; the [AuthError] on failure. A failed
  /// link deliberately does NOT touch the global auth state — the user is
  /// still validly signed in, so the caller surfaces the error locally.
  Future<AuthError?> linkWithGoogle() async {
    try {
      await _service.linkWithGoogle();
    } on AuthException catch (e) {
      return e.authError == AuthError.cancel ? null : e.authError;
    }
    return null;
  }

  /// Links an Apple account to the currently authenticated user.
  Future<AuthError?> linkWithApple() async {
    try {
      await _service.linkWithApple();
    } on AuthException catch (e) {
      return e.authError == AuthError.cancel ? null : e.authError;
    }
    return null;
  }

  /// Creates a new user account with email and password. Failure is
  /// form-local: the error is returned, the global gate never moves.
  Future<AuthError?> createUserWithEmailAndPassword({required String email, required String password}) async {
    //* No e-mail (or any PII) in analytics parameters — Google Analytics policy.
    return await _localFlow(
      () => _service.createUserWithEmailAndPassword(email: email, password: password),
      onSuccess: () => _onSignUp?.call('email_password'),
    );
  }

  /// Signs out. The engine shows the loader between the sign-out and the
  /// automatic anonymous replacement, so the login screen never flashes.
  Future<void> signOut() async {
    await _onSessionEnded();
    await _flow(() => _engine.signOut());
  }

  /// Sends a password reset email to the specified address.
  Future<void> sendPasswordResetEmail({required String email}) async {
    await _service.sendPasswordResetEmail(email: email);
  }

  Future<bool> sendEmailVerification() async {
    try {
      await _service.sendEmailVerification();
      return true;
    } on AuthException {
      return false;
    }
  }

  /// Reloads the provider user: true when the e-mail is verified, false when
  /// not yet, null when the check itself failed. The reload makes
  /// `userChanges` emit; the engine flips the gate on its own.
  Future<bool?> emailVerified() async {
    try {
      return await _service.refreshEmailVerificationStatus();
    } on AuthException {
      return null;
    }
  }

  /// Impersonates another user for admin/support purposes — as a REAL session.
  ///
  //* The endpoint mints `customToken(target, {impersonatedBy: admin})`; the
  //* claim survives restarts and doubles as the return ticket. Refusals are
  //* logged, never surfaced as an auth error — the admin's session is
  //* untouched until the new sign-in lands.
  Future<void> impersonateUserId(String targetUserId) async {
    if (_engine.status.isImpersonating) return;

    final token = await _mintImpersonationToken(targetUserId: targetUserId);
    if (token == null) {
      _log('Impersonation refused for target $targetUserId');
      return;
    }

    await _flow(() => _service.signInWithCustomToken(token));
  }

  /// Stops impersonating and returns to the initiating admin.
  Future<void> stopImpersonating() async {
    if (!_engine.status.isImpersonating) return;

    final token = await _mintImpersonationToken();
    if (token == null) {
      _log('Impersonation return refused — falling back to sign-out');
      await signOut();
      return;
    }

    await _flow(() => _service.signInWithCustomToken(token));
  }

  /// Clears a sticky error and re-resolves from wherever the session is: from
  /// the error screen, or from a loading shell that never finished.
  Future<void> retry() async {
    lastError.value = null;
    _engine.retry();
  }

  void dispose() {
    flowLoader.dispose();
    lastError.dispose();
  }
}
