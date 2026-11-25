import 'package:signals_flutter/signals_flutter.dart';
import 'package:auth_engine/src/auth_error.dart';
import 'package:auth_engine/src/auth_flows.dart';

/// Reactive state for the phone-number OTP login flow.
///
/// Routes all auth interactions through [AuthFlows] so the engine's flow
/// bracket and the loader semantics apply uniformly. Maps error codes
/// to typed [AuthError] values so the UI can put them in its own words.
class PhoneLoginState {
  final AuthFlowsCore<Object?> _flows;

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

    await _flows.startPhoneVerification(
      phoneNumber: number,
      codeSent: (id, token) {
        verificationId.value = id;
        resendToken.value = token;
        isLoading.value = false;
      },
      verificationFailed: (error) {
        errorAuthError.value = error;
        verificationId.value = null;
        isLoading.value = false;
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
      errorAuthError.value = await _flows.signInWithPhone(verificationId: id, smsCode: code);
    } finally {
      //* The page may have closed while the code was checked.
      if (!isLoading.disposed) isLoading.value = false;
    }
  }

  /// Resets verification state so the user can re-enter their number.
  void changePhoneNumber() {
    verificationId.value = null;
    resendToken.value = null;
    smsCode.value = '';
    errorAuthError.value = null;
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
