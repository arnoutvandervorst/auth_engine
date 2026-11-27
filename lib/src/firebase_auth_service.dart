import 'package:auth_engine/src/auth_error.dart';
import 'package:auth_engine/src/auth_service.dart';
import 'package:auth_engine/src/firebase_identity_gateway.dart';
import 'package:firebase_auth/firebase_auth.dart' as fb show PhoneAuthCredential;
import 'package:firebase_auth/firebase_auth.dart' hide PhoneAuthCredential;
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/foundation.dart' show kIsWeb, visibleForTesting;
import 'package:google_sign_in/google_sign_in.dart';

//* google_sign_in 7 wants initialize() exactly once before authenticate();
//* the client ids come from GoogleService-Info.plist / google-services.json.
Future<void>? _googleSignInReady;

Future<GoogleSignIn> _googleSignIn() async {
  try {
    await (_googleSignInReady ??= GoogleSignIn.instance.initialize());
  } catch (_) {
    //* A failed start is not kept: the next attempt initializes again.
    _googleSignInReady = null;
    rethrow;
  }
  return GoogleSignIn.instance;
}

/// What to undo when a step after a provider sign-in fails.
enum SignInUndo {
  /// A returning account: the sign-in created nothing, so only the session ends.
  signOut,

  /// A guest the sign-in linked: take the provider back off and keep the guest
  /// (its uid, document and data).
  unlink,

  /// An account the sign-in created: remove it.
  delete,
}

/// Firebase implementation of AbstractPhoneAuthCredential
class FirebasePhoneAuthCredential extends AbstractPhoneAuthCredential {
  final fb.PhoneAuthCredential credential;

  const FirebasePhoneAuthCredential(this.credential);
}

/// Firebase implementation of AbstractAuthError
class FirebaseAuthError extends AbstractAuthError {
  final FirebaseAuthException exception;

  const FirebaseAuthError(this.exception);

  @override
  String get message => exception.message ?? 'Unknown error';

  @override
  String? get code => exception.code;
}

/// The Firebase auth service both apps run. What belongs to one app comes in
/// through the constructor: its user documents ([AuthAccounts]), its language
/// for Firebase's own e-mails, its log and its failure report.
class FirebaseAuthService<U> implements AuthService<User, U> {
  final _firebaseAuth = FirebaseAuth.instance;
  final AuthAccounts<U> _accounts;
  final String Function() _languageCode;
  final void Function(String message) _log;
  final Future<void> Function(String message, Object error, StackTrace stackTrace) _logException;
  final void Function(AuthFailureStep step, Object error)? _onFailure;

  FirebaseAuthService({
    required this._accounts,
    required this._languageCode,
    required this._log,
    required this._logException,
    this._onFailure,
  });

  /// Maps a [FirebaseAuthException] from a link/credential operation to an [AuthError].
  /// `provider-already-linked` on a phone link is handled by `_attachPhone`
  /// (it replaces the linked number); it is never success on its own.
  AuthError _mapLinkException(FirebaseAuthException e, {required bool isOAuthLink}) {
    return switch (e.code) {
      'credential-already-in-use' => isOAuthLink ? AuthError.emailAlreadyInUse : AuthError.credentialAlreadyInUse,
      'account-exists-with-different-credential' => AuthError.emailAlreadyInUse,
      'invalid-verification-code' => AuthError.invalidVerificationCode,
      _ => e.authError,
    };
  }

  Future<U> _persistNewUser(User authUser) =>
      _accounts.persistNew(uid: authUser.uid, email: authUser.email ?? '', name: authUser.displayName ?? '');

  /// What the provider says about the session — attached to a denied create
  /// so a CI or Crashlytics occurrence explains itself.
  static Future<String> describeIdentity() async {
    final current = FirebaseAuth.instance.currentUser;
    String tokenUid = 'unavailable';
    try {
      tokenUid = (await current?.getIdTokenResult())?.claims?['sub']?.toString() ?? 'none';
    } catch (_) {}
    return 'current=${current?.uid} anonymous=${current?.isAnonymous} '
        'providers=${current?.providerData.length} tokenSub=$tokenUid';
  }

  /// What a failed step after the sign-in undoes, from what the provider
  /// answered: [guestUid] is the guest the sign-in started from (a link keeps
  /// its uid), [isNewUser] whether the sign-in created the account.
  ///
  //* Decided before any document is read. Judged from the document read, a
  //* read that failed (a bad network) deleted a returning account, or the
  //* guest that was just linked.
  @visibleForTesting
  static SignInUndo undoFor({required String uid, required String? guestUid, required bool isNewUser}) {
    if (uid == guestUid) return SignInUndo.unlink;
    return isNewUser ? SignInUndo.delete : SignInUndo.signOut;
  }

  Future<void> _undoSignIn(User authUser, SignInUndo undo, String providerId) async {
    if (_firebaseAuth.currentUser?.uid != authUser.uid) {
      return;
    }

    Future<void> signOut() async {
      try {
        await _firebaseAuth.signOut();
      } catch (signOutError) {
        _log('Unable to sign out auth user ${authUser.uid}: $signOutError');
      }
    }

    switch (undo) {
      case SignInUndo.unlink:
        try {
          await authUser.unlink(providerId);
        } catch (error) {
          _log('Unable to unlink $providerId from guest ${authUser.uid}: $error');
        }
      case SignInUndo.delete:
        try {
          await authUser.delete();
        } catch (error) {
          _log('Unable to delete transient auth user ${authUser.uid}: $error');
          await signOut();
        }
      case SignInUndo.signOut:
        await signOut();
    }
  }

  /// A provider sign-in and what follows it, the same for every provider:
  /// find the account's document (a returning account is done), refuse an
  /// e-mail address or phone number another account holds, then create the
  /// document or promote the guest's in place. Null when the provider gave
  /// no user. A failure after the sign-in undoes what the sign-in itself did
  /// ([undoFor]) and reaches the caller as an [AuthException].
  Future<U?> _signInAndPersist({
    required AuthFailureStep step,
    required String providerId,
    required Future<UserCredential> Function() signIn,
    Future<void> Function(User user)? beforePersist,
  }) async {
    final current = _firebaseAuth.currentUser;
    final guestUid = current != null && current.isAnonymous ? current.uid : null;
    User? authUser;
    var undo = SignInUndo.signOut;

    Future<void> undoSignIn() async {
      final user = authUser;
      if (user != null) await _undoSignIn(user, undo, providerId);
    }

    try {
      final userCredential = await signIn();

      authUser = userCredential.user;
      if (authUser == null) {
        return null;
      }
      undo = undoFor(
        uid: authUser.uid,
        guestUid: guestUid,
        isNewUser: userCredential.additionalUserInfo?.isNewUser ?? false,
      );

      /// See if we have a user with the same UID
      final existingUidUser = await _accounts.getUser(authUser.uid);

      //* A guest document under this uid is the linked GUEST (linking keeps
      //* the uid): promote it below instead of returning it as-is. Returned
      //* as-is, a guest signing up stayed ANONYMOUS: still a "guest" to the
      //* auth engine, no onboarding, no e-mail on file.
      if (_accounts.isReturning(existingUidUser)) {
        return existingUidUser;
      }

      //* An e-mail address or phone number another account holds: we cannot
      //* continue, because we do not know that this person owns it and we do
      //* not want to take over someone else's account.
      final phone = providerId == PhoneAuthProvider.PROVIDER_ID;
      final identifier = phone ? authUser.phoneNumber : authUser.email;
      if (identifier != null) {
        final taken = phone
            ? await _accounts.identifierTaken(phoneNumber: identifier)
            : await _accounts.identifierTaken(email: identifier);
        if (taken) {
          throw AuthException(phone ? AuthError.phoneAlreadyInUse : AuthError.emailAlreadyInUse);
        }
      }

      await beforePersist?.call(authUser);

      /// Create the user document, or promote the existing guest doc in place
      return await _persistNewUser(authUser);
    } on FirebaseAuthException catch (e) {
      _onFailure?.call(step, e);
      await undoSignIn();
      throw AuthException(e.authError);
    } on AuthException {
      await undoSignIn();
      rethrow;
    } catch (error, stackTrace) {
      _onFailure?.call(step, error);
      await undoSignIn();
      //* Every caller in `AuthFlows` catches `on AuthException` only, so
      //* rethrowing the raw error (a Firestore `unavailable` on a bad network,
      //* say) escaped uncaught and left the state pinned on `Authenticating` —
      //* a permanent spinner. Log it, then translate to the contract type.
      await _logException('Auth flow failed', error, stackTrace);
      throw const AuthException(AuthError.unknown);
    }
  }

  /// Runs a call that talks to Firebase Auth and gives its failure as the
  /// one type callers catch.
  Future<T> _translated<T>(Future<T> Function() run) async {
    try {
      return await run();
    } on FirebaseAuthException catch (e) {
      throw AuthException(e.authError);
    }
  }

  @override
  bool requiresEmailVerification(User user) => mustVerifyEmail(user);

  @override
  User? get currentUser {
    return _firebaseAuth.currentUser;
  }

  @override
  Stream<User?> get authStateChanges {
    return _firebaseAuth.authStateChanges();
  }

  @override
  Future<void> signInWithEmailAndPassword({required String email, required String password}) async {
    try {
      await _firebaseAuth.signInWithEmailAndPassword(email: email, password: password);
    } on FirebaseAuthException catch (e) {
      _onFailure?.call(AuthFailureStep.login, e);
      throw AuthException(e.authError);
    }
  }

  @override
  Future<User?> signInAnonymously() async {
    try {
      final userCredential = await _firebaseAuth.signInAnonymously();

      final authUser = userCredential.user;

      if (authUser == null) {
        return null;
      }

      return authUser;
    } on FirebaseAuthException catch (e) {
      throw AuthException(e.authError);
    }
  }

  //* The pending web phone sign-in (see [verifyPhoneNumber]).
  ConfirmationResult? _webPhoneConfirmation;

  Future<UserCredential> _confirmWebPhone(String verificationId, String smsCode) {
    final confirmation = _webPhoneConfirmation;
    if (confirmation == null || confirmation.verificationId != verificationId) {
      throw const AuthException(AuthError.invalidCredential);
    }
    return confirmation.confirm(smsCode);
  }

  @override
  Future<U?> signInWithPhoneCredential({required String verificationId, required String smsCode}) {
    //* Like every other provider: a guest session LINKS, so the uid — and
    //* what the guest was doing — survives. A plain sign-in here
    //* switched uid and abandoned the guest's stack; the returning-account
    //* case (credential already in use) still falls back to sign-in.
    //* The web has no guest: it confirms the code sent by [verifyPhoneNumber].
    return _signInWithPhone(
      () => kIsWeb
          ? _confirmWebPhone(verificationId, smsCode)
          : _signInOrUpgradeAnonymousWithCredential(
              PhoneAuthProvider.credential(verificationId: verificationId, smsCode: smsCode),
            ),
    );
  }

  @override
  Future<U?> signInWithPhoneAuthCredential(AbstractPhoneAuthCredential credential) async {
    if (credential is! FirebasePhoneAuthCredential) {
      throw const AuthException(AuthError.unknown);
    }
    return _signInWithPhone(() => _signInOrUpgradeAnonymousWithCredential(credential.credential));
  }

  Future<U?> _signInWithPhone(Future<UserCredential> Function() signIn) async {
    final user = await _signInAndPersist(
      step: AuthFailureStep.login,
      providerId: PhoneAuthProvider.PROVIDER_ID,
      signIn: signIn,
    );
    if (user == null) {
      throw const AuthException(AuthError.unknown);
    }
    return user;
  }

  @override
  Future<U?> signInWithGoogle() async {
    //* google_sign_in has no authenticate() on web; Firebase's own popup does
    //* the Google round trip there (the host must be an authorized domain).
    if (kIsWeb) return _signInWithGoogle(() => _firebaseAuth.signInWithPopup(GoogleAuthProvider()));
    final String? idToken;
    try {
      // Trigger the authentication flow
      final googleSignInAccount = await (await _googleSignIn()).authenticate();
      // Obtain the auth details from the request
      idToken = googleSignInAccount.authentication.idToken;
    } on GoogleSignInException catch (e) {
      _onFailure?.call(AuthFailureStep.signupGoogle, e);
      //* If the user cancels the login, we throw a specific exception
      if (e.code == GoogleSignInExceptionCode.canceled) {
        throw AuthException(AuthError.cancel);
      }
      //* For other errors, we throw a generic auth exception
      throw AuthException(AuthError.unknown);
    }

    /// When the user cancels the login, return
    if (idToken == null) {
      return null;
    }

    return signInWithGoogleCredential(GoogleAuthProvider.credential(idToken: idToken));
  }

  /// The Firebase half of a Google sign-in, given the provider credential:
  /// link (a guest) or sign in (a returning account), then persist. Split
  /// from [signInWithGoogle] so the emulator suite can drive it with an
  /// emulator-minted Google credential — the plugin UI cannot run there.
  @visibleForTesting
  Future<U?> signInWithGoogleCredential(AuthCredential credential) =>
      _signInWithGoogle(() => _signInOrUpgradeAnonymousWithCredential(credential));

  Future<U?> _signInWithGoogle(Future<UserCredential> Function() signIn) =>
      _signInAndPersist(step: AuthFailureStep.signupGoogle, providerId: 'google.com', signIn: signIn);

  @override
  Future<U?> signInWithApple() => _signInAndPersist(
    step: AuthFailureStep.signupApple,
    providerId: 'apple.com',
    signIn: () => _signInOrUpgradeAnonymousWithProvider(
      AppleAuthProvider()
        ..addScope('email')
        ..addScope('name'),
    ),
  );

  @override
  Future<U> createUserWithEmailAndPassword({required String email, required String password}) async {
    //* Convert the guest in place: if the current session is the auto-created
    //* anonymous user, link email/password to it instead of creating a fresh
    //* account. This keeps the same uid — and therefore any guest
    //* interactions — through onboarding. The social
    //* (Google/Apple) and phone sign-up paths already link; this brings email
    //* in line.
    final currentUser = _firebaseAuth.currentUser;
    if (currentUser != null && currentUser.isAnonymous) {
      return await _upgradeAnonymousWithEmail(currentUser, email, password);
    }

    final user = await _signInAndPersist(
      step: AuthFailureStep.signupEmail,
      providerId: EmailAuthProvider.PROVIDER_ID,
      signIn: () => _firebaseAuth.createUserWithEmailAndPassword(email: email, password: password),
      //* After the collision check, so a taken address gets no verification e-mail.
      beforePersist: (authUser) async {
        await _useAppLanguage();
        await authUser.sendEmailVerification();
      },
    );
    if (user == null) {
      throw const AuthException(AuthError.unknown);
    }
    return user;
  }

  //* Convert the guest in place: link the OAuth credential to the anonymous
  //* session so the uid — and therefore the seeded sample tasks and any guest
  //* interactions — survives signup, exactly like the email path.
  //* `credential-already-in-use` means the OAuth account already exists: that
  //* is a LOGIN, not a signup, so fall back to a plain sign-in (the anonymous
  //* session is abandoned, matching the old behavior for returning users).
  Future<UserCredential> _signInOrUpgradeAnonymousWithCredential(AuthCredential credential) async {
    final currentUser = _firebaseAuth.currentUser;
    if (currentUser != null && currentUser.isAnonymous) {
      try {
        return await currentUser.linkWithCredential(credential);
      } on FirebaseAuthException catch (e) {
        if (e.code != 'credential-already-in-use' && e.code != 'email-already-in-use') {
          rethrow;
        }
        //* Prefer the updated credential Firebase returns for the existing
        //* account — the original one may already be consumed by the link try.
        return await _firebaseAuth.signInWithCredential(e.credential ?? credential);
      }
    }
    return await _firebaseAuth.signInWithCredential(credential);
  }

  //* Provider-flow variant of the guest upgrade (Apple uses signInWithProvider,
  //* which owns the interactive flow, so linking must go through
  //* linkWithProvider). Same login fallback semantics as the credential variant.
  Future<UserCredential> _signInOrUpgradeAnonymousWithProvider(AuthProvider provider) async {
    final currentUser = _firebaseAuth.currentUser;
    if (currentUser != null && currentUser.isAnonymous) {
      try {
        return await currentUser.linkWithProvider(provider);
      } on FirebaseAuthException catch (e) {
        if (e.code != 'credential-already-in-use' && e.code != 'email-already-in-use') {
          rethrow;
        }
        final existingCredential = e.credential;
        if (existingCredential != null) {
          return await _firebaseAuth.signInWithCredential(existingCredential);
        }
        //* No reusable credential returned — rerun the provider flow as a
        //* plain sign-in (one extra provider prompt, rare path).
        //* signInWithProvider is native only; the web uses Firebase's popup.
    if (kIsWeb) return await _firebaseAuth.signInWithPopup(provider);
    return await _firebaseAuth.signInWithProvider(provider);
      }
    }
    return await _firebaseAuth.signInWithProvider(provider);
  }

  /// Upgrades the anonymous [anonUser] to an email/password account by linking
  /// the credential (preserving the uid), then creating the `/users` doc.
  ///
  /// Rollback is deliberately asymmetric:
  /// - If the LINK fails (e.g. email already in use), the anonymous session is
  ///   left untouched — we only surface the error, never take over an account.
  /// - If a step AFTER a successful link fails, the email is unlinked again so
  ///   the guest keeps its uid, document and data (deleting the
  ///   account threw all of that away on a network error).
  Future<U> _upgradeAnonymousWithEmail(User anonUser, String email, String password) async {
    //* Collision guard before touching auth — never link an email that already
    //* belongs to another account.
    final existingEmailUser = await _accounts.identifierTaken(email: email);
    if (existingEmailUser) {
      throw AuthException(AuthError.emailAlreadyInUse);
    }

    try {
      final credential = EmailAuthProvider.credential(email: email, password: password);
      await anonUser.linkWithCredential(credential);
    } on FirebaseAuthException catch (e) {
      _onFailure?.call(AuthFailureStep.signupEmail, e);
      //* Link failed → anonymous session intact, just report the error.
      throw AuthException(_mapLinkException(e, isOAuthLink: false));
    }

    final linkedUser = _firebaseAuth.currentUser;
    if (linkedUser == null) {
      throw AuthException(AuthError.unknown);
    }

    var completed = false;
    try {
      await _useAppLanguage();
      await linkedUser.sendEmailVerification();
      //* The canonical promotion: linking kept the uid, so the guest document
      //* is upgraded rather than replaced.
      final addedUser = await _persistNewUser(linkedUser);
      completed = true;
      return addedUser;
    } catch (error, stackTrace) {
      _onFailure?.call(AuthFailureStep.signupEmail, error);
      if (!completed) {
        await _undoSignIn(linkedUser, SignInUndo.unlink, EmailAuthProvider.PROVIDER_ID);
      }
      await _logException('Anonymous email upgrade failed', error, stackTrace);
      throw const AuthException(AuthError.unknown);
    }
  }

  @override
  Future<void> signInWithCustomToken(String token) async {
    try {
      await _firebaseAuth.signInWithCustomToken(token);
    } on FirebaseAuthException catch (e) {
      throw AuthException(e.authError);
    }
  }

  @override
  Future<void> signOut() async {
    await _firebaseAuth.signOut();
  }

  @override
  Future<void> sendPasswordResetEmail({required String email}) => _translated(() async {
    await _useAppLanguage();
    await _firebaseAuth.sendPasswordResetEmail(email: email);
  });

  /// Auth's own e-mails (verify, password reset) follow the app's language;
  /// without it they fall back to the console default.
  Future<void> _useAppLanguage() => _firebaseAuth.setLanguageCode(_languageCode());

  @override
  Future<void> sendEmailVerification() async {
    final user = _firebaseAuth.currentUser;

    if (user == null || !requiresEmailVerification(user)) {
      throw AuthException(AuthError.invalidAuthUser);
    }

    //* A second tap soon after the first answers `too-many-requests`.
    await _translated(() async {
      await _useAppLanguage();
      await user.sendEmailVerification();
    });
  }

  @override
  Future<bool> refreshEmailVerificationStatus() async {
    final user = _firebaseAuth.currentUser;

    if (user == null || !requiresEmailVerification(user)) {
      return false;
    }

    //* Rules may read `email_verified` from the ID token: refresh it first, so
    //* whatever the reload below sets off already writes with the new claim.
    //* Offline both calls fail: the caller gets an [AuthException], not a raw one.
    return _translated(() async {
      await user.getIdToken(true);
      await user.reload();
      return _firebaseAuth.currentUser?.emailVerified ?? false;
    });
  }

  @override
  Future<U?> getUser(String uid) => _accounts.getUser(uid);

  @override
  Future<U> waitForUser(String uid) => _accounts.waitForUser(uid);

  @override
  Future<void> deleteUser(U user) => _accounts.delete(user);

  @override
  Future<String?> pushInstallationId() async {
    //* No push on the web: it would ask for notification permission and
    //* needs a service worker.
    if (kIsWeb) return null;
    try {
      final messaging = FirebaseMessaging.instance;
      //* The FID comes through onRegistered, also when already registered: listen first.
      final registered = messaging.onRegistered.first;
      await messaging.register();
      final fid = await registered.timeout(const Duration(seconds: 5));
      return fid.isEmpty ? null : fid;
    } catch (error) {
      _log('Unable to register for push: $error');
      return null;
    }
  }

  @override
  Future<String?> legacyDeviceToken() async {
    if (kIsWeb) return null;
    try {
      //* The one use of the token API left: finding this device's old token to
      //* take it off the account (only while the account still holds
      //* tokens). Remove with the `tokens` field.
      // ignore: deprecated_member_use
      final token = await FirebaseMessaging.instance.getToken();
      return (token == null || token.isEmpty) ? null : token;
    } catch (error) {
      _log('Unable to get the legacy device token: $error');
      return null;
    }
  }

  @override
  Future<void> verifyPhoneNumber({
    required String phoneNumber,
    required void Function(String verificationId, int? resendToken) codeSent,
    required void Function(AbstractPhoneAuthCredential credential) verificationCompleted,
    required void Function(AbstractAuthError exception) verificationFailed,
    required void Function(String verificationId) codeAutoRetrievalTimeout,
  }) async {
    //* verifyPhoneNumber is native only. On the web Firebase checks for a bot
    //* (invisible reCAPTCHA), sends the SMS and hands back a confirmation that
    //* [signInWithPhoneCredential] completes with the code.
    if (kIsWeb) {
      try {
        final confirmation = await _firebaseAuth.signInWithPhoneNumber(phoneNumber);
        _webPhoneConfirmation = confirmation;
        codeSent(confirmation.verificationId, null);
      } on FirebaseAuthException catch (e) {
        verificationFailed(FirebaseAuthError(e));
      }
      return;
    }
    await _firebaseAuth.verifyPhoneNumber(
      phoneNumber: phoneNumber,
      verificationCompleted: (fb.PhoneAuthCredential credential) {
        verificationCompleted(FirebasePhoneAuthCredential(credential));
      },
      verificationFailed: (FirebaseAuthException exception) {
        verificationFailed(FirebaseAuthError(exception));
      },
      codeSent: codeSent,
      codeAutoRetrievalTimeout: codeAutoRetrievalTimeout,
    );
  }

  @override
  Future<bool> linkWithCredential({required String verificationId, required String smsCode}) async {
    final currentUser = _firebaseAuth.currentUser;
    if (currentUser == null) {
      throw AuthException(AuthError.invalidAuthUser);
    }

    try {
      final credential = PhoneAuthProvider.credential(verificationId: verificationId, smsCode: smsCode);
      await _attachPhone(currentUser, credential);
      return true;
    } on FirebaseAuthException catch (e) {
      _onFailure?.call(AuthFailureStep.phoneLink, e);
      // credential-already-in-use: the number belongs to another account —
      // a verification error, never a silent takeover.
      throw AuthException(_mapLinkException(e, isOAuthLink: false));
    }
  }

  @override
  Future<bool> linkWithPhoneAuthCredential(AbstractPhoneAuthCredential credential) async {
    final currentUser = _firebaseAuth.currentUser;
    if (currentUser == null) {
      throw AuthException(AuthError.invalidAuthUser);
    }

    if (credential is! FirebasePhoneAuthCredential) {
      throw AuthException(AuthError.unknown);
    }

    try {
      //* The credential Firebase hands us directly on Android
      //* auto-verification; same semantics as linkWithCredential.
      await _attachPhone(currentUser, credential.credential);
      return true;
    } on FirebaseAuthException catch (e) {
      _onFailure?.call(AuthFailureStep.phoneLink, e);
      throw AuthException(_mapLinkException(e, isOAuthLink: false));
    }
  }

  /// Puts the verified number on the auth record, which onRequestPhoneSync
  /// then copies to the private doc. A first number is LINKED; a changed one
  /// REPLACES the linked one (`updatePhoneNumber`). Linking a second phone
  /// credential always fails with `provider-already-linked`, and that used to
  /// count as success: the old number stayed on the account while the app
  /// showed the new one as verified — possibly without even checking the SMS
  /// code (docs/OPEN_ISSUES.md H8). Both paths verify the code server-side.
  Future<void> _attachPhone(User user, fb.PhoneAuthCredential credential) async {
    final hasPhone = user.providerData.any((info) => info.providerId == PhoneAuthProvider.PROVIDER_ID);
    try {
      if (hasPhone) {
        await user.updatePhoneNumber(credential);
      } else {
        await user.linkWithCredential(credential);
      }
    } on FirebaseAuthException catch (e) {
      //* A phone linked meanwhile (another device, a stale providerData).
      //* Any other failure is reported once, by the caller.
      if (e.code != 'provider-already-linked') rethrow;
      await user.updatePhoneNumber(credential);
    }
    await user.reload();
  }

  @override
  String? get linkedPhoneNumber {
    final phone = _firebaseAuth.currentUser?.phoneNumber;
    return (phone == null || phone.isEmpty) ? null : phone;
  }

  @override
  List<String> get linkedProviderIds {
    return _firebaseAuth.currentUser?.providerData.map((p) => p.providerId).toList() ?? [];
  }

  @override
  Future<void> linkWithGoogle() async {
    final currentUser = _firebaseAuth.currentUser;
    if (currentUser == null) {
      throw AuthException(AuthError.invalidAuthUser);
    }

    try {
      final googleSignInAccount = await (await _googleSignIn()).authenticate();
      final googleAuth = googleSignInAccount.authentication;

      if (googleAuth.idToken == null) {
        throw AuthException(AuthError.cancel);
      }

      final credential = GoogleAuthProvider.credential(idToken: googleAuth.idToken);
      await currentUser.linkWithCredential(credential);
      await currentUser.reload();
    } on GoogleSignInException catch (e) {
      if (e.code == GoogleSignInExceptionCode.canceled) {
        throw AuthException(AuthError.cancel);
      }
      throw AuthException(AuthError.unknown);
    } on FirebaseAuthException catch (e) {
      if (e.code == 'provider-already-linked') {
        await currentUser.reload();
        return;
      }
      throw AuthException(_mapLinkException(e, isOAuthLink: true));
    }
  }

  @override
  Future<void> linkWithApple() async {
    final currentUser = _firebaseAuth.currentUser;
    if (currentUser == null) {
      throw AuthException(AuthError.invalidAuthUser);
    }

    try {
      final appleProvider = AppleAuthProvider()
        ..addScope('email')
        ..addScope('name');
      await currentUser.linkWithProvider(appleProvider);
      await currentUser.reload();
    } on FirebaseAuthException catch (e) {
      if (e.code == 'provider-already-linked') {
        await currentUser.reload();
        return;
      }
      throw AuthException(_mapLinkException(e, isOAuthLink: true));
    }
  }
}
