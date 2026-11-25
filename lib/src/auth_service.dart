import 'package:firebase_auth/firebase_auth.dart' as auth;

/// Abstract phone authentication credential
abstract class AbstractPhoneAuthCredential {
  const AbstractPhoneAuthCredential();
}

/// Abstract authentication error for phone verification
abstract class AbstractAuthError {
  const AbstractAuthError();
  String get message;
  String? get code;
}

/// The auth service: [T] is the provider's user, [U] the app's user document.
abstract interface class AuthService<T, U> {
  const AuthService();

  /// Returns the currently authenticated provider user, if one exists.
  T? get currentUser;

  /// Emits provider-level auth changes from the backing auth SDK.
  Stream<T?> get authStateChanges;

  /// Signs in with an email/password combination.
  Future<void> signInWithEmailAndPassword({required String email, required String password});

  /// Signs in anonymously and returns the provider user, if available.
  Future<auth.User?> signInAnonymously();

  /// Signs in with a server-minted custom token (impersonation start/return).
  Future<void> signInWithCustomToken(String token);

  /// Starts a Google sign-in flow and returns the synced app user.
  Future<U?> signInWithGoogle();

  /// Starts an Apple sign-in flow and returns the synced app user.
  Future<U?> signInWithApple();

  /// Creates an email/password account and returns the synced app user.
  Future<U> createUserWithEmailAndPassword({required String email, required String password});

  /// Signs out the current user from the provider and local app state.
  Future<void> signOut();

  /// Loads an app user by UID.
  Future<U?> getUser(String uid);

  /// Waits until the app user document exists and can be read.
  Future<U> waitForUser(String uid);

  /// Deletes the authenticated provider user and related app resources.
  Future<void> deleteUser(U user);

  /// This install's push target: its Firebase Installation ID (FID), or null
  /// when messaging has none yet (or on the web). Persisting it is the app's job.
  Future<String?> pushInstallationId();

  /// This device's legacy FCM token, or null. Only for taking it off the
  /// account once the FID is there; nothing sends to it after that.
  Future<String?> legacyDeviceToken();

  /// Sends a password-reset email.
  Future<void> sendPasswordResetEmail({required String email});

  /// Sends a verification email to the current user.
  Future<void> sendEmailVerification();

  /// Reloads the provider user and returns whether email verification is complete.
  Future<bool> refreshEmailVerificationStatus();

  /// Returns whether the given provider user should go through the app's email verification flow.
  bool requiresEmailVerification(T user);

  /// Phone authentication methods
  Future<void> verifyPhoneNumber({
    required String phoneNumber,
    required void Function(String verificationId, int? resendToken) codeSent,
    required void Function(AbstractPhoneAuthCredential credential) verificationCompleted,
    required void Function(AbstractAuthError exception) verificationFailed,
    required void Function(String verificationId) codeAutoRetrievalTimeout,
  });

  /// Links the current account with an SMS verification code.
  Future<bool> linkWithCredential({required String verificationId, required String smsCode});

  /// Links the current account with an auto-retrieved phone credential (the
  /// Android instant/auto-verification path of [verifyPhoneNumber]).
  Future<bool> linkWithPhoneAuthCredential(AbstractPhoneAuthCredential credential);

  /// The phone number linked to the authenticated account, or null when no
  /// phone provider is linked. This is the only trustworthy "verified" signal —
  /// UI must not infer verification from anything client-side.
  String? get linkedPhoneNumber;

  /// Signs in using an SMS verification code.
  Future<U?> signInWithPhoneCredential({required String verificationId, required String smsCode});

  /// Returns the provider IDs currently linked to the authenticated user (e.g. 'google.com', 'apple.com', 'password').
  List<String> get linkedProviderIds;

  /// Links Google to the current authenticated account.
  Future<void> linkWithGoogle();

  /// Links Apple to the current authenticated account.
  Future<void> linkWithApple();
}

/// The app's user documents, as the auth service needs them. One per app:
/// it knows that app's model, its sign-up document and its backend lookup.
abstract interface class AuthAccounts<U> {
  /// The user document for [uid], or null when there is none.
  Future<U?> getUser(String uid);

  /// Waits until the user document for [uid] exists and can be read.
  Future<U> waitForUser(String uid);

  /// Whether a provider sign-in found a RETURNING account (return its
  /// document as it is) rather than a guest to promote: a link keeps the
  /// guest's uid, so its guest document is found under the same id and must
  /// go through [persistNew] instead.
  bool isReturning(U? existing);

  /// Creates the user document for a new account, or promotes the guest
  /// document under the same [uid] in place.
  Future<U> persistNew({required String uid, required String email, required String name});

  /// Removes the account's document and what hangs off it.
  Future<void> delete(U user);

  /// Whether another account already holds [email] / [phoneNumber]. Must fail
  /// closed (throw) when it cannot tell: a silent pass could take over
  /// someone else's account.
  Future<bool> identifierTaken({String? email, String? phoneNumber});
}

/// Where an auth step failed, for the app's failure log.
enum AuthFailureStep { login, signupGoogle, signupApple, signupEmail, phoneLink }
