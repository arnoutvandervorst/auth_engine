import 'package:auth_engine/src/auth_status.dart';

/// The two seams between the auth engine and the world.
///
//* Two, and deliberately no third for side effects. The current notifier
//* reaches into a composer, the app badge, analytics — which is how
//* auth came to transitively depend on half the app, and why constructing it
//* in a test touches live SDKs. Here those concerns simply do not exist:
//* sign-out cleanup belongs to whoever calls `signOut`, at the call site.
//* An engine that cannot name a side effect cannot grow a dependency on it.

/// The identity provider (Firebase Auth, or a fake).
abstract interface class IdentityGateway {
  /// Session changes, including in-place user mutations (phone link, email
  /// verification) — not just sign-in/sign-out edges.
  Stream<Session> get changes;

  /// The provider's session right now, without claims. The engine reads it
  /// only when an anonymous round ends with no guest on the stream.
  Session get current;

  /// Create an anonymous session. The result arrives via [changes]. False
  /// when the provider already held a guest: nothing new, nothing emitted.
  Future<bool> ensureAnonymousSession();

  /// End the current session. The resulting `NoneSession` arrives via [changes].
  Future<void> endSession();

  /// Re-ask the backend for the guest `/users` document. Idempotent. The
  /// engine calls it when a guest session has no document after the sign-in
  /// round — a double failure of the ensure call used to be terminal for
  /// that install (no content for the guest's whole life, no error).
  Future<void> ensureGuestDoc();
}

/// The profile document store (Firestore, or a fake).
abstract interface class ProfileGateway {
  /// One-shot read. Null when the document does not exist — which is routine,
  /// not exceptional: a guest document is created by the backend and races
  /// first launch. Throws only on real failure (offline, denied).
  Future<Profile?> fetch(String uid);

  /// Live updates for one profile. Null emissions mean "document absent".
  Stream<Profile?> changes(String uid);
}

/// A failure already translated into app terms. Anything else that escapes a
/// gateway or a flow is treated as [AuthIssue.undetermined] — it must still
/// reach the UI as a failure rather than a hang.
class AuthFlowException implements Exception {
  final AuthIssue issue;

  const AuthFlowException(this.issue);

  @override
  String toString() => 'AuthFlowException(${issue.name})';
}

/// Maps any thrown object onto an [AuthIssue].
AuthIssue issueOf(Object error) => error is AuthFlowException ? error.issue : AuthIssue.undetermined;
