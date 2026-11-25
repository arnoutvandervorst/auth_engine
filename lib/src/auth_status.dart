/// Auth, as one immutable value with derived answers.
library;

//* No imports. The auth core depends on a handful of facts — who the provider
//* says you are, what stage your profile document is in, whether a sign-in
//* flow is mid-flight — not on Firebase, not on signals, and not on the
//* sixty-field `User` model. Keeping this file import-free is the enforcement
//* of that, not a style choice.

/// What the identity provider currently holds for this device.
sealed class Session {
  const Session();

  String? get uid;
}

/// No provider session at all. Transient: the engine reacts by requesting an
/// anonymous session, so the app never *rests* here.
class NoneSession extends Session {
  const NoneSession();

  @override
  String? get uid => null;
}

/// An anonymous provider session. Exists so a fresh install can browse demo
/// stacks and vote before creating an account.
class GuestSession extends Session {
  @override
  final String uid;

  const GuestSession({required this.uid});
}

/// A provider session with an identity attached.
class AccountSession extends Session {
  @override
  final String uid;
  final String? email;

  /// Whether the provider has seen this email verified.
  final bool emailVerified;

  /// True only for password accounts — federated providers (Google, Apple)
  /// verified the address themselves, and gating them would strand the user
  /// on a screen whose button cannot help.
  final bool mustVerifyEmail;

  /// The phone number LINKED at the provider, or null.
  ///
  //* Published as a fact, never used as a gate. Phone verification is the
  //* onboarding step that proves a real person, so `AccountStage.onboarding`
  //* already covers "not proven yet" — and the provider link is the only
  //* trustworthy signal, since a profile field is a claim a client can write.
  final String? verifiedPhone;

  /// The admin uid this session was minted FOR, or null for a real sign-in.
  ///
  //* Impersonation done properly: an admin-gated endpoint mints a custom
  //* token for the target with this claim, the admin signs in with it, and
  //* `request.auth.uid` IS the target — every rule, query and trigger answers
  //* "what would this user see" for free, because nothing is pretending.
  //* The old design was a view overlay while the token still said "admin":
  //* state and provider disagreed about who was asking, writes as the target
  //* were rejected or landed as the admin's, and the state machine had to
  //* model the lie. As a session fact, impersonation stops being auth STATE
  //* at all — the banner and its "return" button key off this field, and the
  //* gate needs no special case: you see their disabled screen because you
  //* are, for every layer, them.
  final String? impersonatedBy;

  const AccountSession({
    required this.uid,
    this.email,
    this.emailVerified = false,
    this.mustVerifyEmail = false,
    this.verifiedPhone,
    this.impersonatedBy,
  });
}

/// Lifecycle stage of the profile document.
enum AccountStage {
  /// The document behind an anonymous session. Every session gets a document —
  /// an identity that is not stored cannot be rate-limited, counted or banned,
  /// and guests vote.
  guest,
  onboarding,
  active,
  disabled,
  expired,

  /// The stored stage did not parse.
  ///
  //* `UserStatus` is mapper-defaulted to `unknown`, the house parse fallback,
  //* so this value asserts only "could not tell" — an absent field and a
  //* status newer than this build both land here. It must never be collapsed
  //* into a real stage: `onboarding` re-runs a stepper the user finished,
  //* `active` ignores whatever the backend actually set.
  undetermined,
}

/// The slice of the user document auth actually reads.
class Profile {
  final String uid;
  final AccountStage stage;

  /// The profile's stored phone number (what contact invites resolve against).
  /// Backend-owned; carried here for display and diagnostics only.
  final String? phoneNumber;

  const Profile({required this.uid, required this.stage, this.phoneNumber});
}

/// Why something failed, in app terms.
enum AuthIssue { network, cancelled, badCredentials, emailTaken, undetermined }

/// What the UI should render. Always derived, never stored.
enum AuthGate { loading, anonymous, onboarding, disabled, expired, ready, failed }

/// The complete auth state at one instant.
class AuthStatus {
  final Session session;

  /// The profile for [session]'s uid, once loaded.
  final Profile? profile;

  /// A surfaced failure. Sticky until [AuthEngine.retry] or a session change.
  final AuthIssue? issue;

  /// Interactive sign-in flows currently in flight.
  ///
  //* The bracket that tells the engine a `NoneSession` is the middle of a
  //* sign-in (signOut → credential landing), not a device that needs an
  //* anonymous session. Without it, sign-out races the automatic anonymous
  //* sign-in: two sign-ins, two uids, a state that settles and then flips.
  final int busyFlows;

  const AuthStatus({
    this.session = const NoneSession(),
    this.profile,
    this.issue,
    this.busyFlows = 0,
  });

  /// The admin behind this session, when it was minted by impersonation.
  ///
  //* Derived from the SESSION, because impersonation is a real session with a
  //* claim — not an overlay this class has to maintain. The UI banner and its
  //* "return" button are the only consumers.
  String? get impersonatedBy => switch (session) {
    AccountSession(:final impersonatedBy) => impersonatedBy,
    _ => null,
  };

  bool get isImpersonating => impersonatedBy != null;

  AuthGate get gate {
    if (issue != null) return AuthGate.failed;

    return switch (session) {
      NoneSession() => AuthGate.loading,
      //* A guest's gate never consults the profile: the document is created by
      //* the backend and races first launch, and a guest has nothing to be
      //* locked out of. Browsing and voting must not wait on Firestore.
      GuestSession() => AuthGate.anonymous,
      //* An unverified email is a NUDGE, not a wall: a password sign-up used
      //* to land here instead of onboarding, unmounting the page the guest
      //* had been voting on until the mailbox round-trip. See
      //* [needsEmailVerification].
      AccountSession() => _stageGate(),
    };
  }

  /// A password account whose address is still unverified. Rendered as a
  /// banner above the content; it never gates anything.
  bool get needsEmailVerification => switch (session) {
    AccountSession(:final mustVerifyEmail, :final emailVerified) => mustVerifyEmail && !emailVerified,
    _ => false,
  };

  AuthGate _stageGate() {
    final current = profile;
    if (current == null) return AuthGate.loading;

    return switch (current.stage) {
      //* An account still carrying `guest` is the upgrade window: linking kept
      //* the uid and the document, promotion has not landed yet. Onboarding is
      //* where that user belongs.
      AccountStage.guest || AccountStage.onboarding => AuthGate.onboarding,
      AccountStage.active => AuthGate.ready,
      AccountStage.disabled => AuthGate.disabled,
      AccountStage.expired => AuthGate.expired,
      //* A stage that did not parse is a failure to determine state — which is
      //* what `failed` already means: settled, surfaced, retryable. Naming a
      //* cause ("app too old") would be a guess.
      AccountStage.undetermined => AuthGate.failed,
    };
  }

  /// Whether boot can stop waiting.
  ///
  //* Derived, not stored. The predecessor of this idea was a `Completer` that
  //* many code paths each had to remember to complete exactly once; forgetting
  //* one presents as "stuck on the splash screen forever". A derived property
  //* cannot be forgotten on a new path.
  bool get settled => gate != AuthGate.loading;

  /// Whether the user may move around the app freely.
  ///
  //* No impersonation special case: the "return to my account" control lives
  //* on a banner floating ABOVE the gated UI, so the admin can always leave
  //* without the gate having to lie about navigability.
  bool get canNavigate => switch (gate) {
    AuthGate.ready || AuthGate.anonymous || AuthGate.onboarding => true,
    _ => false,
  };

  /// Whose content the app should render, or null when there is nothing to show.
  String? get viewerId => switch (gate) {
    AuthGate.ready || AuthGate.onboarding || AuthGate.disabled || AuthGate.expired => profile?.uid,
    AuthGate.anonymous => session.uid,
    _ => null,
  };

  /// The phone number this account has proven it controls, or null.
  String? get verifiedPhoneNumber => switch (session) {
    AccountSession(:final verifiedPhone) => verifiedPhone,
    _ => null,
  };

  /// The issue to render when [gate] is [AuthGate.failed].
  ///
  //* The gate can fail with [issue] unset — an `undetermined` stage arrives as
  //* a SUCCESSFUL load carrying a value nobody could read.
  AuthIssue? get displayIssue => gate == AuthGate.failed ? (issue ?? AuthIssue.undetermined) : null;

  AuthStatus copyWith({
    Session? session,
    Profile? profile,
    bool clearProfile = false,
    AuthIssue? issue,
    bool clearIssue = false,
    int? busyFlows,
  }) {
    return AuthStatus(
      session: session ?? this.session,
      profile: clearProfile ? null : profile ?? this.profile,
      issue: clearIssue ? null : issue ?? this.issue,
      busyFlows: busyFlows ?? this.busyFlows,
    );
  }

  @override
  String toString() =>
      'AuthStatus(gate: ${gate.name}, uid: ${session.uid}, stage: ${profile?.stage.name}, '
      'impersonatedBy: $impersonatedBy, issue: ${issue?.name}, busyFlows: $busyFlows)';
}
