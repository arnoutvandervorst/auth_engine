import 'dart:async';

import 'package:auth_engine/auth_engine.dart';
import 'package:firebase_auth/firebase_auth.dart' as fb;
import 'package:flutter_test/flutter_test.dart';

//* `fb.User` cannot be constructed outside the SDK, which is why `sessionOf`
//* has no test here; the token reads take a function and are pinned below.
void main() {
  group('impersonation claim read', () {
    const short = Duration(milliseconds: 50);

    test('reads the claim from the token', () async {
      expect(await FirebaseIdentityGateway.impersonationClaim(() async => {'impersonatedBy': 'admin1'}), 'admin1');
      expect(await FirebaseIdentityGateway.impersonationClaim(() async => null), isNull);
    });

    test('a token read that never returns gives up, so later sessions are not held back', () async {
      final never = Completer<Map<String, dynamic>?>();
      expect(await FirebaseIdentityGateway.impersonationClaim(() => never.future, timeout: short), isNull);
    });

    test('a signed-out user (no-current-user) reads as no claim, not a crash', () async {
      expect(
        await FirebaseIdentityGateway.impersonationClaim(() async => throw fb.FirebaseAuthException(code: 'no-current-user')),
        isNull,
      );
    });
  });

  group('guestStillHeld', () {
    test('a guest whose token reads is held', () async {
      expect(await FirebaseIdentityGateway.guestStillHeld(() async => 'token'), isTrue);
    });

    test('no-current-user means the SDK already signed that guest out', () async {
      expect(
        await FirebaseIdentityGateway.guestStillHeld(() async => throw fb.FirebaseAuthException(code: 'no-current-user')),
        isFalse,
      );
    });

    test('a network error or a slow read leaves the guest in place', () async {
      expect(
        await FirebaseIdentityGateway.guestStillHeld(() async => throw fb.FirebaseAuthException(code: 'network-request-failed')),
        isTrue,
      );
      expect(
        await FirebaseIdentityGateway.guestStillHeld(
          () => Completer<String?>().future,
          timeout: const Duration(milliseconds: 10),
        ),
        isTrue,
      );
    });
  });
}
