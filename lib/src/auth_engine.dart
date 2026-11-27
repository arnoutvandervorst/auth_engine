import 'dart:async';

import 'package:auth_engine/src/auth_gateways.dart';
import 'package:auth_engine/src/auth_status.dart';

/// How long after a failed guest-doc ensure round the engine retries once.
const kGuestDocRepairDelay = Duration(seconds: 30);

/// How long a finished anonymous round waits for its guest to come down the
/// stream before the engine looks again.
const kGuestArrivalGrace = Duration(seconds: 2);

/// How many rounds in a row may end without a session before the engine
/// shows the retry screen instead of trying again.
const kMaxEmptyGuestRounds = 3;

/// The auth orchestrator. Auth only — nothing else.
///
//* THE RULE THAT MAKES THIS TESTABLE: every state transition in this class is
//* synchronous. No method reads `_status`, awaits, and then writes it. Async
//* work happens in callbacks that deliver a fact — "a profile for uid X
//* arrived", "the provider now says Y" — and each fact carries the uid it
//* belongs to, so relevance is one comparison at write time. In single-threaded
//* Dart that discipline removes transition interleaving entirely: there is
//* nothing for a generation counter, a lock, or an event queue to defend
//* against, so this class has none of them.
//*
//* And it is auth ONLY. The notifier this replaces grew to 845 lines because
//* badges, group membership, coin balances and metric aggregates accreted onto
//* the one object that everything could already see. Those belong to feature
//* states that WATCH auth; the engine cannot even name them (see
//* `auth_gateways.dart` on the missing side-effect seam).
class AuthEngine {
  final IdentityGateway _identity;
  final ProfileGateway _profiles;

  AuthStatus _status = const AuthStatus();
  final _changes = StreamController<AuthStatus>.broadcast();

  StreamSubscription<Session>? _sessionSub;
  StreamSubscription<Profile?>? _profileSub;

  /// Guards the automatic anonymous sign-in: at most one in flight, ever.
  bool _ensuringAnonymous = false;

  /// Bumped on every `NoneSession` arrival. Lets the supervisor tell "still
  /// the sign-out I am already answering" from "a NEW sign-out landed while I
  /// was busy" — the latter needs another round, the former must not get one.
  int _signOutEpoch = 0;

  //* Grace between one-shot profile fetch retries. Injectable so tests can
  //* collapse it to zero — production keeps the default.
  final Duration _profileRetryDelay;

  //* See [kGuestArrivalGrace]; injectable for the same reason.
  final Duration _guestArrivalGrace;

  /// Anonymous rounds in a row that ended without a session.
  int _emptyGuestRounds = 0;
  bool _disposed = false;

  AuthEngine({
    required this._identity,
    required this._profiles,
    this._profileRetryDelay = const Duration(seconds: 1),
    this._guestArrivalGrace = kGuestArrivalGrace,
  });

  /// The current state. Always coherent — see the synchronous-transition rule.
  AuthStatus get status => _status;

  /// Every state, as it changes.
  Stream<AuthStatus> get changes => _changes.stream;

  /// Completes at the first settled status. Boot awaits this.
  ///
  //* Derived from state (`AuthStatus.settled`), so no code path has to
  //* remember to complete anything.
  Future<AuthStatus> get ready =>
      _status.settled ? Future.value(_status) : _changes.stream.firstWhere((next) => next.settled);

  void start() {
    _sessionSub = _identity.changes.listen(_sessionChanged);
  }

  // ---------------------------------------------------------------------------
  // Facts arriving
  // ---------------------------------------------------------------------------

  void _sessionChanged(Session next) {
    if (next is NoneSession) {
      _signOutEpoch++;
    } else {
      _emptyGuestRounds = 0;
    }

    final previous = _status.session;
    final sameIdentity = previous.runtimeType == next.runtimeType && previous.uid == next.uid;

    if (sameIdentity) {
      //* Token refresh, email-verification reload, phone link: the same user,
      //* with session fields possibly changed. Keep the loaded profile —
      //* re-fetching would flicker the app back through `loading` on every
      //* provider tick.
      _publish(_status.copyWith(session: next));
      _superviseSession();
      _repairGuestDoc();
      return;
    }

    //* A different identity is a fresh slate: the old profile and errors
    //* describe someone who is no longer here. The flow bracket survives — it
    //* describes work in flight, not a person. This same path carries the
    //* anonymous upgrade (same uid, different session kind) AND impersonation
    //* in both directions (a minted target session in, the admin's return
    //* ticket out) — none of them need special handling.
    _publish(AuthStatus(session: next, busyFlows: _status.busyFlows));
    _followProfile();
    _superviseSession();
  }

  void _profileArrived(String forUid, Profile? profile) {
    //* Stale-result drop. A slow load for a session we already left carries
    //* the old uid; one comparison retires it. This replaces hand-rolled
    //* mutual exclusion (generation counters checked after every await) with
    //* data.
    if (_status.session.uid != forUid) return;
    if (profile == null) return; // Absent: keep waiting on the live stream.

    _publish(_status.copyWith(profile: profile, clearIssue: true));
  }

  void _profileFailed(String forUid, Object error, {int attempt = 0}) {
    if (_status.session.uid != forUid) return;

    //* A guest's document is created by the backend and races first launch —
    //* a failed read must never put an error screen in front of someone who
    //* can browse and vote perfectly well.
    if (_status.session is GuestSession) return;

    //* Bounded retry BEFORE surfacing: the one-shot read races the auth-token
    //* rotation right after sign-in (a beat of permission-denied), and failing
    //* the gate here flashed the "Try again" error screen mid-login while the
    //* live stream was about to deliver the profile anyway. Two retries cover
    //* the race; each is dropped if the session moved on or the stream already
    //* delivered.
    if (attempt < 2) {
      Future<void>.delayed(_profileRetryDelay, () {
        if (_disposed || _status.session.uid != forUid) return;
        if (_status.profile != null) return;
        _profiles.fetch(forUid).then((profile) => _profileArrived(forUid, profile)).catchError((Object retryError) {
          _profileFailed(forUid, retryError, attempt: attempt + 1);
        });
      });
      return;
    }

    //* For an account this SETTLES the machine (gate `failed`), it does not
    //* hang it. The alternative — swallowing the error and staying `loading` —
    //* is the "stuck on splash forever" class of bug.
    _publish(_status.copyWith(issue: issueOf(error)));
  }

  // ---------------------------------------------------------------------------
  // Intents
  // ---------------------------------------------------------------------------

  /// Runs an interactive sign-in flow, bracketed so the engine knows any
  /// mid-flow `NoneSession` is expected. Returns null on failure, with the
  /// issue surfaced on [status].
  Future<T?> runFlow<T>(Future<T> Function() flow) async {
    _publish(_status.copyWith(busyFlows: _status.busyFlows + 1, clearIssue: true));
    try {
      return await flow();
    } catch (error) {
      _publish(_status.copyWith(issue: issueOf(error)));
      return null;
    } finally {
      _publish(_status.copyWith(busyFlows: _status.busyFlows - 1));
      //* The bracket suppressed the anonymous fallback; whoever lowers the
      //* last bracket must re-check, or a signed-out device rests on a
      //* spinner with nobody responsible for recovering it.
      _superviseSession();
    }
  }

  /// Signs out. Cleanup of session-scoped app state (composer drafts, caches)
  /// is the CALLER's job at the call site — the engine does not know those
  /// things exist.
  Future<void> signOut() => runFlow(() async {
    //* The stale view goes immediately; the `NoneSession` from the provider
    //* arrives via the stream and the supervisor then requests the anonymous
    //* replacement. In between the gate is `loading`, so the login screen
    //* never flashes.
    _publish(_status.copyWith(clearProfile: true));
    await _identity.endSession();
  });

  //* No impersonate()/stopImpersonating() here, deliberately. Impersonation
  //* is a REAL session minted by an admin-gated endpoint (custom token with
  //* an `impersonatedBy` claim): entering and leaving are ordinary sign-ins
  //* wrapped in `runFlow` at the call site, and they arrive through the
  //* provider stream like any other session change. The engine has nothing
  //* to do — which is the point. The overlay this replaces kept a second
  //* profile the state machine had to maintain, gate around, and shadow-
  //* compare as a permanent special case.

  /// Clears a surfaced failure and re-resolves from wherever the session
  /// actually is.
  void retry() {
    _emptyGuestRounds = 0;
    _publish(_status.copyWith(clearIssue: true));
    if (_status.session.uid != null) {
      _followProfile();
    }
    _superviseSession();
  }

  // ---------------------------------------------------------------------------
  // Effects
  // ---------------------------------------------------------------------------

  /// How often a dropped live subscription is opened again for one session.
  static const _maxProfileResubscribes = 3;

  void _followProfile({int resubscribe = 0}) {
    _profileSub?.cancel();
    _profileSub = null;

    final uid = _status.session.uid;
    if (uid == null) return;

    //* Guests are followed too — the document IS wanted (vote accounting,
    //* rate limits, the ban handle); it just never gates rendering. One-shot
    //* fetch for latency, live stream for every later change; both deliver
    //* uid-keyed facts and last-write-wins on the same document.
    _profiles.fetch(uid).then((profile) => _profileArrived(uid, profile)).catchError((Object error) {
      _profileFailed(uid, error);
    });

    _profileSub = _profiles.changes(uid).listen(
      //* Keyed by the uid ON the document, not the uid this subscription was
      //* opened for — so even a subscription that outlives its cancellation
      //* (or a gateway that multiplexes) cannot smuggle someone else's
      //* profile in under the current session's key.
      (profile) {
        if (profile != null) _profileArrived(profile.uid, profile);
      },
      onError: (Object _) {
        //* A dropped live subscription is not a reason to fail a session the
        //* one-shot fetch already resolved. But a stream that ended on an
        //* error delivers nothing more (a denied read in the token rotation
        //* right after sign-in), and a later change — onboarding to active —
        //* would never arrive: open it again, a few times, each later.
        if (resubscribe >= _maxProfileResubscribes) return;
        Future<void>.delayed(_profileRetryDelay * (resubscribe + 1), () {
          if (_disposed || _status.session.uid != uid) return;
          _followProfile(resubscribe: resubscribe + 1);
        });
      },
    );
  }

  /// The one standing invariant: the machine never rests without a session.
  void _superviseSession() {
    if (_disposed) return;
    if (_status.session is! NoneSession) return;
    if (_status.busyFlows > 0) return; // An interactive flow owns this gap.
    if (_ensuringAnonymous) return;

    _ensuringAnonymous = true;
    final epoch = _signOutEpoch;
    var created = true;
    _identity
        .ensureAnonymousSession()
        .then((value) => created = value)
        .catchError((Object error) {
          if (_status.session is NoneSession) {
            _publish(_status.copyWith(issue: issueOf(error)));
          }
          return true; // A failed round adopts nothing.
        })
        .whenComplete(() {
          //* Reset the guard, but do NOT re-invoke here: on success the guest
          //* session arrives via the stream a beat after this future resolves,
          //* and re-invoking in that window double-signs-in. Recovery from a
          //* failure goes through `retry()` or the next provider tick.
          _ensuringAnonymous = false;

          //* One exception: a sign-out that landed WHILE this round was in
          //* flight (the guest arrived, then left again) was refused by the
          //* guard above, and no provider tick is coming to answer it — the
          //* device would rest on a spinner. The guest-doc ensure call made
          //* this round long enough to hit in practice (test-to-test churn).
          //* A bumped epoch means exactly that; a plain failure leaves it put.
          if (_signOutEpoch != epoch) _superviseSession();

          //* A round that created nothing and left the engine without a session:
          //* the provider already holds a guest whose event arrived BEFORE the
          //* sign-out's NoneSession (Android delivers them in that order when a
          //* sign-out lands mid-round). A sign-in would return that same user and
          //* emit nothing, so the device would rest on
          //* `loading` (release gate, 2026-11-09). Adopt it; its later stream
          //* emission, if any, is the same-identity path.
          final now = _identity.current;
          if (!created && _signOutEpoch == epoch && _status.session is NoneSession && now is GuestSession) {
            _sessionChanged(now);
          }

          //* The round is over. A guest with no document now had BOTH ensure
          //* attempts fail — schedule one repair rather than resting on an
          //* install that looks fine and never gets content.
          if (_signOutEpoch == epoch && _status.session is GuestSession && _status.profile == null) {
            Future<void>.delayed(kGuestDocRepairDelay, _repairGuestDoc);
          }

          //* The round is over and there is still no session, with nothing
          //* above answering it: the guest it created never came down the
          //* stream. Android, a sign-out landing while the sign-in is in
          //* flight: the SDK signs the new guest out again and no event tells
          //* the engine (release gate, 2026-11-25). Give the stream a beat,
          //* then look again rather than rest on `loading` for good.
          if (_status.session is NoneSession && _status.issue == null) {
            Future<void>.delayed(_guestArrivalGrace, _recheckSession);
          }
        });
  }

  /// Runs another anonymous round when the last one left the engine without
  /// a session; after [kMaxEmptyGuestRounds] of those, the retry screen.
  void _recheckSession() {
    if (_disposed) return;
    if (_status.session is! NoneSession || _status.issue != null) return;
    if (_status.busyFlows > 0 || _ensuringAnonymous) return; // Their end re-checks.

    if (++_emptyGuestRounds > kMaxEmptyGuestRounds) {
      _publish(_status.copyWith(issue: AuthIssue.undetermined));
      return;
    }
    _superviseSession();
  }

  /// One in-flight repair at a time; every later provider tick (token
  /// refresh, roughly hourly) re-arms it while the document stays missing.
  bool _repairingGuestDoc = false;

  void _repairGuestDoc() {
    if (_disposed) return;
    if (_status.session is! GuestSession) return;
    if (_status.profile != null) return;
    if (_ensuringAnonymous || _repairingGuestDoc) return;
    _repairingGuestDoc = true;
    final uid = _status.session.uid;
    _identity
        .ensureGuestDoc()
        .then((_) {
          //* The live stream delivers the document once it lands; a one-shot
          //* re-read covers a stream that was opened before it existed.
          if (!_disposed && _status.session.uid == uid) _followProfile();
        })
        .catchError((Object _) {})
        .whenComplete(() => _repairingGuestDoc = false);
  }

  void _publish(AuthStatus next) {
    if (identical(next, _status)) return;
    _status = next;
    if (!_changes.isClosed) _changes.add(next);
  }

  Future<void> dispose() async {
    _disposed = true;
    await _sessionSub?.cancel();
    await _profileSub?.cancel();
    await _changes.close();
  }
}
