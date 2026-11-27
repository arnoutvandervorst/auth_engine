import 'package:signals_flutter/signals_flutter.dart';
import 'package:auth_engine/src/auth_error.dart';
import 'package:auth_engine/src/auth_flows.dart';

/// Reactive state for the phone-number OTP login flow.
///
/// Routes all auth interactions through [AuthFlows] so the engine's flow
/// bracket and the loader semantics apply uniformly. Maps error codes
/// to typed [AuthError] values so the UI can put them in its own words.
class PhoneLoginState {
  //* A getter, not the flows themselves: an app's flows are a global that
  //* wakes Firebase on first touch, and showing the form must not do that.
  final AuthFlowsCore<Object?> Function() _flows;

  final phoneNumber = Signal<String>('', options: SignalOptions(name: 'PhoneLoginState.phoneNumber'));
  final smsCode = Signal<String>('', options: SignalOptions(name: 'PhoneLoginState.smsCode'));
  final verificationId = Signal<String?>(null, options: SignalOptions(name: 'PhoneLoginState.verificationId'));
  final resendToken = Signal<int?>(null, options: SignalOptions(name: 'PhoneLoginState.resendToken'));
  final isLoading = Signal<bool>(false, options: SignalOptions(name: 'PhoneLoginState.isLoading'));
  final errorAuthError = Signal<AuthError?>(null, options: SignalOptions(name: 'PhoneLoginState.errorAuthError'));

  late final Computed<bool> codeSent;

  PhoneLoginState(this._flows) {
    codeSent = computed(
      () => verificationId.value != null,
      options: ComputedOptions(name: 'PhoneLoginState.codeSent'),
    );
  }

  /// Sends the OTP for the current [phoneNumber]. Populates [verificationId]
  /// + [resendToken] on success, [errorAuthError] on failure.
  Future<void> sendOtp() async {
    final number = phoneNumber.value.trim();
    if (number.isEmpty) {
      errorAuthError.value = AuthError.invalidCredential;
      return;
    }

    isLoading.value = true;
    errorAuthError.value = null;

    await _flows().startPhoneVerification(
      phoneNumber: number,
      //* The page may have closed while the code was sent: no writes after dispose.
      codeSent: (id, token) {
        _set(verificationId, id);
        _set(resendToken, token);
        _set(isLoading, false);
      },
      //* Android verified the number without a code: no code step follows.
      verificationCompleted: (credential) async {
        final error = await _flows().signInWithVerifiedPhone(credential);
        _set(errorAuthError, error);
        _set(isLoading, false);
      },
      verificationFailed: (error) {
        _set(errorAuthError, error);
        _set(verificationId, null);
        _set(isLoading, false);
      },
    );
  }

  /// Submits [smsCode] against the active [verificationId].
  Future<void> submitOtp() async {
    final code = smsCode.value.trim();
    final id = verificationId.value;
    if (code.isEmpty) {
      errorAuthError.value = AuthError.invalidVerificationCode;
      return;
    }
    if (id == null) {
      errorAuthError.value = AuthError.invalidCredential;
      return;
    }

    isLoading.value = true;
    errorAuthError.value = null;

    try {
      //* Failure is form-local: the returned error renders on the OTP step.
      _set(errorAuthError, await _flows().signInWithPhone(verificationId: id, smsCode: code));
    } finally {
      //* The page may have closed while the code was checked.
      _set(isLoading, false);
    }
  }

  /// Resets verification state so the user can re-enter their number.
  void changePhoneNumber() {
    verificationId.value = null;
    resendToken.value = null;
    smsCode.value = '';
    errorAuthError.value = null;
  }

  /// Writes [value] unless the state was disposed (the page closed mid-flow).
  void _set<T>(Signal<T> signal, T value) {
    if (!signal.disposed) signal.value = value;
  }

  void dispose() {
    codeSent.dispose();
    errorAuthError.dispose();
    isLoading.dispose();
    phoneNumber.dispose();
    resendToken.dispose();
    smsCode.dispose();
    verificationId.dispose();
  }
}
