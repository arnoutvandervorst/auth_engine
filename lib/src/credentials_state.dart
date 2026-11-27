import 'package:signals_flutter/signals_flutter.dart';
import 'package:auth_engine/src/auth_error.dart';

/// The e-mail + password form's state. An app extends it with its own rules:
/// what a valid e-mail is and when a new password is strong enough.
class CredentialsStateCore {
  final bool Function(String email) _isEmailValid;
  final bool Function(String password) _isPasswordStrong;

  final username = Signal('');
  final password = Signal('');

  /// Form-local error from the last interactive sign-in/register attempt.
  /// Failure stays on the page (the global auth gate never moves for these
  /// flows); editing either field clears it.
  final authError = Signal<AuthError?>(null);

  /// An interactive sign-in/register is in flight. Every trigger on the page
  /// (button, keyboard "go", Google, Apple) disables on it and shows it.
  final busy = Signal(false);

  late final Computed<bool> isUserNameValid;
  late final Computed<bool> isPasswordValid;
  late final Computed<bool> isValid;

  /// Sign-in needs a valid e-mail and any password: the strength rules are
  /// for new passwords only, so an account whose password was set elsewhere
  /// (Firebase's reset page allows 6 characters) can still sign in.
  late final Computed<bool> canSignIn;

  CredentialsStateCore({required this._isEmailValid, required this._isPasswordStrong}) {
    isUserNameValid = Computed<bool>(() => _isEmailValid(username.value));
    isPasswordValid = Computed<bool>(() => _isPasswordStrong(password.value));
    isValid = Computed<bool>(() => isUserNameValid.value && isPasswordValid.value);
    canSignIn = Computed<bool>(() => isUserNameValid.value && password.value.isNotEmpty);
  }

  /// Set the username/email field
  void setUserName(String value) {
    username.value = value;
    authError.value = null;
  }

  /// Set the password field
  void setPassword(String value) {
    password.value = value;
    authError.value = null;
  }

  /// Runs one interactive auth [flow] unless one is already in flight, under
  /// [busy]; its error lands on [authError]. True when it ran and succeeded.
  Future<bool> run(Future<AuthError?> Function() flow) async {
    if (busy.value) return false;
    busy.value = true;
    try {
      final error = await flow();
      //* A sign-in that went through often closes the page (and disposes this
      //* state) while the flow still runs: no writes after dispose.
      if (!authError.disposed) authError.value = error;
      return error == null;
    } finally {
      if (!busy.disposed) busy.value = false;
    }
  }

  /// Dispose the signal
  void dispose() {
    username.dispose();
    password.dispose();
    authError.dispose();
    busy.dispose();
    isUserNameValid.dispose();
    isPasswordValid.dispose();
    isValid.dispose();
    canSignIn.dispose();
  }
}
