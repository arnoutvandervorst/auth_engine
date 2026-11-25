import 'package:firebase_auth/firebase_auth.dart';

/// Why an interactive auth step did not go through. The app gives each value
/// its words (an extension with `title`); the package only names them.
enum AuthError {
  cancel,
  emailAlreadyInUse,
  phoneAlreadyInUse,
  invalidEmail,
  invalidCredential,
  operationNotAllowed,
  weakPassword,
  userDisable,
  userNotFound,
  tooManyRequests,
  wrongPassword,
  invalidAuthUser,
  invalidIdentityToken,
  credentialAlreadyInUse,
  invalidVerificationCode,
  unknown,
}

/// The one exception type the auth service throws: callers catch this.
class AuthException implements Exception {
  final AuthError authError;

  const AuthException(this.authError);
}

extension FirebaseAuthExceptionExtension on FirebaseAuthException {
  AuthError get authError {
    return switch (code) {
      "ERROR_INVALID_EMAIL" || "invalid-email" => AuthError.invalidEmail,
      "ERROR_WRONG_PASSWORD" || "wrong-password" => AuthError.wrongPassword,
      "ERROR_USER_NOT_FOUND" ||
      "user-not-found" ||
      "firebase_auth/user-not-found" ||
      "auth/user-not-found" => AuthError.userNotFound,
      "ERROR_USER_DISABLED" || "user-disabled" => AuthError.userDisable,
      "ERROR_TOO_MANY_REQUESTS" || "too-many-requests" => AuthError.tooManyRequests,
      "ERROR_OPERATION_NOT_ALLOWED" || "operation-not-allowed" => AuthError.operationNotAllowed,
      "ERROR_EMAIL_ALREADY_IN_USE" ||
      "account-exists-with-different-credential" ||
      "email-already-in-use" => AuthError.emailAlreadyInUse,
      "auth/invalid-credential" || "invalid-credential" => AuthError.invalidCredential,
      _ => AuthError.unknown,
    };
  }
}
