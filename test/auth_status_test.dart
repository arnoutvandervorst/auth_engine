import 'package:flutter_test/flutter_test.dart';
import 'package:auth_engine/auth_engine.dart';

/// The derivation layer: given facts, what should the app show?
///
//* Pure values in, pure values out — no fakes, no async, no timing. This is
//* most of the auth decision surface, and every case here is a case the
//* current notifier can only express as an integration test.
void main() {
  const uid = 'user-1';
  const account = AccountSession(uid: uid, verifiedPhone: '+31600000000');
  const active = Profile(uid: uid, stage: AccountStage.active);

  AuthStatus signedIn({Session session = account, Profile? profile = active}) =>
      AuthStatus(session: session, profile: profile);

  group('the gate', () {
    test('no session is loading', () {
      expect(const AuthStatus().gate, AuthGate.loading);
      expect(const AuthStatus().settled, isFalse);
    });

    test('a guest is anonymous, with or without their document', () {
      //* The guest document is created by the backend and races first launch.
      //* Browsing and voting must never wait on it — and no stage in it may
      //* lock a guest out, because a guest has nothing to be locked out of.
      const session = GuestSession(uid: uid);

      expect(signedIn(session: session, profile: null).gate, AuthGate.anonymous);
      expect(
        signedIn(session: session, profile: const Profile(uid: uid, stage: AccountStage.guest)).gate,
        AuthGate.anonymous,
      );
      expect(
        signedIn(session: session, profile: const Profile(uid: uid, stage: AccountStage.undetermined)).gate,
        AuthGate.anonymous,
      );
    });

    test('an account without its profile is still loading', () {
      expect(signedIn(profile: null).gate, AuthGate.loading);
    });

    test('each stage routes to its own gate', () {
      const cases = {
        AccountStage.guest: AuthGate.onboarding,
        AccountStage.onboarding: AuthGate.onboarding,
        AccountStage.active: AuthGate.ready,
        AccountStage.disabled: AuthGate.disabled,
        AccountStage.expired: AuthGate.expired,
      };

      cases.forEach((stage, expected) {
        expect(signedIn(profile: Profile(uid: uid, stage: stage)).gate, expected, reason: '$stage');
      });
    });

    test('an account still staged guest is onboarding — the upgrade window', () {
      //* Linking an anonymous account keeps the uid and the document; the
      //* stage promotion lands separately, so this in-between state is real.
      expect(signedIn(profile: const Profile(uid: uid, stage: AccountStage.guest)).gate, AuthGate.onboarding);
    });

    test('a stage that did not parse fails rather than guesses', () {
      //* `undetermined` is the parse fallback: an absent field and a status
      //* newer than this build both land there. Guessing `onboarding` re-runs
      //* a finished stepper; guessing `active` ignores what the backend set.
      final status = signedIn(profile: const Profile(uid: uid, stage: AccountStage.undetermined));

      expect(status.gate, AuthGate.failed);
      expect(status.settled, isTrue, reason: 'failed is settled — boot must stop waiting');
      expect(status.issue, isNull, reason: 'the load SUCCEEDED; the value was unreadable');
      expect(status.displayIssue, AuthIssue.undetermined, reason: 'the error screen still needs something to say');
    });

    test('an unverified password email is a nudge, never a gate', () {
      const session = AccountSession(uid: uid, email: 'a@b.com', mustVerifyEmail: true, emailVerified: false);
      //* No profile yet → loading, exactly like a verified account; the
      //* address is surfaced through needsEmailVerification instead.
      expect(const AuthStatus(session: session).gate, AuthGate.loading);
      expect(const AuthStatus(session: session).needsEmailVerification, isTrue);
      const verified = AccountSession(uid: uid, email: 'a@b.com', mustVerifyEmail: true, emailVerified: true);
      expect(const AuthStatus(session: verified).needsEmailVerification, isFalse);
    });

    test('a federated account is never gated on email', () {
      const session = AccountSession(uid: uid, email: 'a@b.com', mustVerifyEmail: false, emailVerified: false);

      expect(signedIn(session: session).gate, AuthGate.ready);
    });

    test('a surfaced issue fails the gate regardless of everything else', () {
      expect(signedIn().copyWith(issue: AuthIssue.network).gate, AuthGate.failed);
    });
  });

  group('derived answers', () {
    test('settled is derived, so no code path can forget to set it', () {
      expect(const AuthStatus().settled, isFalse);
      expect(signedIn().settled, isTrue);
      expect(const AuthStatus(session: GuestSession(uid: uid)).settled, isTrue);
      expect(const AuthStatus(issue: AuthIssue.network).settled, isTrue);
    });

    test('viewerId picks the right identity per gate', () {
      expect(signedIn().viewerId, uid);
      expect(const AuthStatus(session: GuestSession(uid: 'g1')).viewerId, 'g1');
      expect(const AuthStatus().viewerId, isNull);
      expect(const AuthStatus(issue: AuthIssue.network).viewerId, isNull);
    });

    test('the verified phone is published from the session, never the profile', () {
      //* The profile's number is a stored claim; the provider link is the
      //* evidence. Auth publishes the fact — gating on it is onboarding's job.
      expect(signedIn().verifiedPhoneNumber, '+31600000000');
      expect(const AuthStatus(session: GuestSession(uid: uid)).verifiedPhoneNumber, isNull);
      expect(
        signedIn(session: const AccountSession(uid: uid)).verifiedPhoneNumber,
        isNull,
        reason: 'no link, no claim — whatever the profile says',
      );
    });
  });

  group('impersonation — a session fact, not an overlay', () {
    //* A minted session IS the target's session, carrying only a claim naming
    //* the admin it was created for. The state machine has no second profile
    //* to maintain: the gate, viewerId, everything answers for the target
    //* because for every layer the target is who is signed in.
    const minted = AccountSession(uid: 'user-2', impersonatedBy: uid);

    test('the claim is the only trace', () {
      final status = signedIn(
        session: minted,
        profile: const Profile(uid: 'user-2', stage: AccountStage.active),
      );

      expect(status.isImpersonating, isTrue);
      expect(status.impersonatedBy, uid);
      expect(status.gate, AuthGate.ready);
      expect(status.viewerId, 'user-2');
    });

    test('the admin sees what the user sees — including a disabled screen', () {
      final status = signedIn(
        session: minted,
        profile: const Profile(uid: 'user-2', stage: AccountStage.disabled),
      );

      expect(status.gate, AuthGate.disabled);
      //* No forced-navigability hack: the "return to my account" control
      //* floats on a banner ABOVE the gated UI, keyed off `isImpersonating`.
      expect(status.canNavigate, isFalse);
    });

    test('a real sign-in carries no claim', () {
      expect(signedIn().isImpersonating, isFalse);
      expect(signedIn().impersonatedBy, isNull);
    });
  });
}
