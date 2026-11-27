import 'package:auth_engine/auth_engine.dart';
import 'package:auth_engine/testing.dart';
import 'package:firebase_auth/firebase_auth.dart' as fb;
import 'package:flutter_test/flutter_test.dart';
import 'package:signals_flutter/signals_flutter.dart';

/// The flows, the composed view and the form states, against a fake service.

class _Credential extends AbstractPhoneAuthCredential {
  const _Credential();
}

class _Service implements AuthService<fb.User, Object?> {
  final calls = <String>[];
  Object? signInError;
  Object? resendError;
  Object? checkError;
  Object? verifyError;

  /// Verify answers like Android's instant verification: a credential, no code.
  bool instant = false;

  @override
  Future<void> signInWithEmailAndPassword({required String email, required String password}) async {
    if (signInError != null) throw signInError!;
  }

  /// No user: the person closed the Google sheet.
  @override
  Future<Object?> signInWithGoogle() async => null;

  @override
  Future<void> sendEmailVerification() async {
    if (resendError != null) throw resendError!;
  }

  @override
  Future<bool> refreshEmailVerificationStatus() async {
    if (checkError != null) throw checkError!;
    return true;
  }

  @override
  Future<void> verifyPhoneNumber({
    required String phoneNumber,
    required void Function(String verificationId, int? resendToken) codeSent,
    required void Function(AbstractPhoneAuthCredential credential) verificationCompleted,
    required void Function(AbstractAuthError exception) verificationFailed,
    required void Function(String verificationId) codeAutoRetrievalTimeout,
  }) async {
    if (verifyError != null) throw verifyError!;
    instant ? verificationCompleted(const _Credential()) : codeSent('id-1', null);
  }

  @override
  Future<Object?> signInWithPhoneAuthCredential(AbstractPhoneAuthCredential credential) async {
    calls.add('phoneCredential');
    return 'user';
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  late FakeIdentity identity;
  late FakeProfiles profiles;
  late AuthEngine engine;
  late _Service service;
  late AuthFlowsCore<Object?> flows;
  final logins = <String>[];

  setUp(() {
    logins.clear();
    identity = FakeIdentity();
    profiles = FakeProfiles();
    engine = AuthEngine(identity: identity, profiles: profiles, profileRetryDelay: Duration.zero)..start();
    service = _Service();
    flows = AuthFlowsCore<Object?>(
      engine: engine,
      service: service,
      onSessionEnded: () async {},
      mintImpersonationToken: ({String? targetUserId}) async => null,
      log: (_) {},
      onLogin: logins.add,
    );
  });

  tearDown(() async {
    flows.dispose();
    await engine.dispose();
    await identity.close();
    await profiles.close();
  });

  group('form-local sign-in', () {
    test('a credential failure comes back to the form; the gate and the analytics do not move', () async {
      service.signInError = const AuthException(AuthError.wrongPassword);
      expect(await flows.signInWithEmailAndPassword(email: 'a@b.c', password: 'x'), AuthError.wrongPassword);
      expect(engine.status.issue, isNull);
      expect(flows.lastError.value, isNull);
      expect(logins, isEmpty);
    });

    test('an unexpected failure comes back as unknown, not as a sign-in that went through', () async {
      service.signInError = StateError('the plugin failed to start');
      expect(await flows.signInWithEmailAndPassword(email: 'a@b.c', password: 'x'), AuthError.unknown);
      expect(engine.status.issue, isNull);
      expect(logins, isEmpty);
    });

    test('analytics hears a sign-in that went through, not a cancelled one', () async {
      expect(await flows.signInWithGoogle(), isNull);
      expect(logins, isEmpty);
      expect(await flows.signInWithEmailAndPassword(email: 'a@b.c', password: 'x'), isNull);
      expect(logins, ['email_password']);
    });
  });

  test('a failed resend or check answers false / null instead of throwing', () async {
    service.resendError = const AuthException(AuthError.tooManyRequests);
    service.checkError = const AuthException(AuthError.unknown);
    expect(await flows.sendEmailVerification(), isFalse);
    expect(await flows.emailVerified(), isNull);
  });

  test('closing the provider popup or sheet is a cancel, not a failure', () {
    for (final code in ['popup-closed-by-user', 'cancelled-popup-request', 'canceled', 'web-context-canceled']) {
      expect(fb.FirebaseAuthException(code: code).authError, AuthError.cancel, reason: code);
    }
    expect(fb.FirebaseAuthException(code: 'something-new').authError, AuthError.unknown);
  });

  group('phone', () {
    test('a verification that throws ends the spinner with an error; the gate stays', () async {
      service.verifyError = StateError('reCAPTCHA did not load');
      final state = PhoneLoginState(() => flows)..phoneNumber.value = '+31612345678';
      await state.sendOtp();
      expect(state.isLoading.value, isFalse);
      expect(state.errorAuthError.value, AuthError.unknown);
      expect(engine.status.issue, isNull);
      state.dispose();
    });

    test('a number verified without a code signs in and ends the spinner', () async {
      service.instant = true;
      final state = PhoneLoginState(() => flows)..phoneNumber.value = '+31612345678';
      await state.sendOtp();
      await pump();
      expect(service.calls, ['phoneCredential']);
      expect(state.isLoading.value, isFalse);
      expect(state.errorAuthError.value, isNull);
      state.dispose();
    });
  });

  test('a form closed while its sign-in runs writes nothing after dispose', () async {
    final credentials = CredentialsStateCore(isEmailValid: (_) => true, isPasswordStrong: (_) => true);
    final ran = credentials.run(() async {
      credentials.dispose();
      return null;
    });
    expect(await ran, isTrue);
  });

  test('the view composes the gate: a running flow loads, a flow error fails, else the engine speaks', () {
    final status = signal(const AuthStatus(session: GuestSession(uid: 'g')));
    final loader = signal(0);
    final error = signal<AuthError?>(null);
    final view = AuthView(status: status, flowLoader: loader, lastError: error);
    expect(view.gate.value, AuthGate.anonymous);
    expect(view.viewerId.value, 'g');
    loader.value = 1;
    expect(view.gate.value, AuthGate.loading);
    expect(view.viewerId.value, isNull);
    loader.value = 0;
    error.value = AuthError.wrongPassword;
    expect(view.gate.value, AuthGate.failed);
    expect(view.displayError.value, AuthError.wrongPassword);
    view.dispose();
  });

  group('what a failed step after the sign-in undoes', () {
    SignInUndo undo({String? guest, bool isNew = false}) =>
        FirebaseAuthService.undoFor(uid: 'u1', guestUid: guest, isNewUser: isNew);

    test('a returning account is never deleted: only its session ends', () {
      expect(undo(), SignInUndo.signOut);
      expect(undo(guest: 'another-guest'), SignInUndo.signOut);
    });

    test('a linked guest keeps its account: the provider comes off', () {
      expect(undo(guest: 'u1'), SignInUndo.unlink);
      expect(undo(guest: 'u1', isNew: true), SignInUndo.unlink);
    });

    test('an account the sign-in created is removed', () {
      expect(undo(isNew: true), SignInUndo.delete);
    });
  });

  group('the live profile', () {
    const uid = 'user-1';

    test('a stream that drops is opened again, and its later change arrives', () async {
      profiles.store[uid] = const Profile(uid: uid, stage: AccountStage.onboarding);
      identity.emit(const AccountSession(uid: uid));
      await pump();
      expect(engine.status.gate, AuthGate.onboarding);
      expect(profiles.watched, [uid]);

      profiles.fail(StateError('permission-denied'));
      await pump();
      expect(profiles.watched, [uid, uid]);
      expect(engine.status.gate, AuthGate.onboarding);

      profiles.push(const Profile(uid: uid, stage: AccountStage.active));
      await pump();
      expect(engine.status.gate, AuthGate.ready);
    });

    test('a stream that keeps dropping is given up on, not opened forever', () async {
      profiles.store[uid] = const Profile(uid: uid, stage: AccountStage.active);
      identity.emit(const AccountSession(uid: uid));
      await pump();
      for (var i = 0; i < 6; i++) {
        profiles.fail(StateError('permission-denied'));
        await pump();
      }
      expect(profiles.watched.length, 4);
      expect(engine.status.gate, AuthGate.ready);
    });
  });
}
