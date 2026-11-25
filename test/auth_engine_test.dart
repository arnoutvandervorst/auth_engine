import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:auth_engine/auth_engine.dart';

import 'package:auth_engine/testing.dart';

/// The orchestration layer, against two small fakes.
///
//* Each fake is a handful of lines because each gateway asks one question.
//* The races that matter — a slow load for an abandoned session, sign-out vs
//* the automatic anonymous sign-in — are driven DETERMINISTICALLY here with
//* held completers, which is precisely what cannot be done against a live
//* backend and why they have no unit coverage today.

void main() {
  late FakeIdentity identity;
  late FakeProfiles profiles;
  late AuthEngine engine;

  const uid = 'user-1';
  const account = AccountSession(uid: uid);
  const active = Profile(uid: uid, stage: AccountStage.active);

  setUp(() {
    identity = FakeIdentity();
    profiles = FakeProfiles()..store[uid] = active;
    engine = AuthEngine(identity: identity, profiles: profiles, profileRetryDelay: Duration.zero)..start();
  });

  tearDown(() async {
    await engine.dispose();
    await identity.close();
    await profiles.close();
  });

  group('cold start', () {
    test('a signed-out device gets exactly one anonymous session', () async {
      identity.emit(const NoneSession());

      final settled = await engine.ready;

      expect(settled.gate, AuthGate.anonymous);
      expect(identity.calls, ['anonymous']);
    });

    test('a returning account resolves to ready', () async {
      identity.emit(account);

      final settled = await engine.ready;

      expect(settled.gate, AuthGate.ready);
      expect(settled.profile?.uid, uid);
    });

    test('the guest document is followed but never awaited', () async {
      //* The document IS wanted — vote accounting, rate limits, a ban handle —
      //* but the backend creates it, so it may not exist yet. The gate must
      //* not care.
      identity.emit(const NoneSession());
      final settled = await engine.ready;
      await pump();

      expect(settled.gate, AuthGate.anonymous);
      expect(profiles.fetched, contains(settled.session.uid), reason: 'the doc is followed');
      expect(engine.status.profile, isNull, reason: 'absent doc, gate unaffected');

      //* And when the backend catches up, the document lands silently.
      profiles.push(Profile(uid: settled.session.uid!, stage: AccountStage.guest));
      await pump();

      expect(engine.status.profile?.stage, AccountStage.guest);
      expect(engine.status.gate, AuthGate.anonymous, reason: 'still a guest');
    });

    test('a guest profile failure is invisible', () async {
      profiles.fetchError = const AuthFlowException(AuthIssue.network);
      identity.emit(const NoneSession());

      final settled = await engine.ready;
      await pump();

      expect(settled.gate, AuthGate.anonymous);
      expect(engine.status.issue, isNull, reason: 'a guest has nothing to be locked out of');
    });

    test('an account profile failure settles as failed — never hangs', () async {
      //* The "stuck on splash forever" class of bug: a throw during the
      //* profile load must surface with a retry, not strand the boot await.
      profiles.fetchError = const AuthFlowException(AuthIssue.network);
      identity.emit(account);

      final settled = await engine.ready;

      expect(settled.gate, AuthGate.failed);
      expect(settled.issue, AuthIssue.network);
    });

    test('a transient first-fetch failure never flashes failed — the stream delivers', () async {
      //* The login "Try again" flash: the one-shot read races the auth-token
      //* rotation right after sign-in. One lost fetch must not fail the gate
      //* while the live stream is healthy. A REAL (small) retry delay here —
      //* with Duration.zero the retries exhaust inside one pump and the
      //* pre-delivery window this test pins would be unobservable.
      final localIdentity = FakeIdentity()..autoEmitGuest = false;
      final localProfiles = FakeProfiles();
      final localEngine = AuthEngine(
        identity: localIdentity,
        profiles: localProfiles,
        profileRetryDelay: const Duration(milliseconds: 60),
      )..start();
      addTearDown(localEngine.dispose);
      addTearDown(localProfiles.close);

      localProfiles.fetchError = const AuthFlowException(AuthIssue.network);
      localIdentity.emit(account);
      await pump();

      expect(localEngine.status.gate, AuthGate.loading, reason: 'first failure retries instead of surfacing');
      expect(localEngine.status.issue, isNull);

      //* The live stream delivers while the retry window is open.
      localProfiles.push(Profile(uid: account.uid, stage: AccountStage.active));
      await pump();

      expect(localEngine.status.gate, AuthGate.ready);

      //* Let the retry timers fire into the already-delivered profile: they
      //* must no-op, not resurrect the failure.
      await Future<void>.delayed(const Duration(milliseconds: 200));
      expect(localEngine.status.gate, AuthGate.ready);
      expect(localEngine.status.issue, isNull, reason: 'no failed flash anywhere in the sequence');
    });

    test('a transient failure recovered by the RETRY fetch also never fails', () async {
      final localIdentity = FakeIdentity()..autoEmitGuest = false;
      final localProfiles = FakeProfiles();
      final localEngine = AuthEngine(
        identity: localIdentity,
        profiles: localProfiles,
        profileRetryDelay: const Duration(milliseconds: 60),
      )..start();
      addTearDown(localEngine.dispose);
      addTearDown(localProfiles.close);

      localProfiles.fetchError = const AuthFlowException(AuthIssue.network);
      localProfiles.store[account.uid] = Profile(uid: account.uid, stage: AccountStage.active);
      localIdentity.emit(account);
      await pump();
      expect(localEngine.status.gate, AuthGate.loading);

      //* First fetch failed; clear the fault so the scheduled retry succeeds.
      localProfiles.fetchError = null;
      await Future<void>.delayed(const Duration(milliseconds: 200));

      expect(localEngine.status.gate, AuthGate.ready);
      expect(localEngine.status.issue, isNull);
    });

    test('a raw non-auth throw still surfaces as a failure', () async {
      profiles.fetchError = StateError('firestore exploded');
      identity.emit(account);

      final settled = await engine.ready;

      expect(settled.gate, AuthGate.failed);
      expect(settled.issue, AuthIssue.undetermined);
    });
  });

  group('staleness — driven deterministically', () {
    test('a slow load for an abandoned session cannot win', () async {
      profiles
        ..holdFetch = Completer<void>()
        ..store['user-2'] = const Profile(uid: 'user-2', stage: AccountStage.onboarding);

      identity.emit(account);
      await pump();
      identity.emit(const AccountSession(uid: 'user-2'));
      await pump();

      //* Both fetches release together; user-1's answer arrives late and must
      //* be dropped by its uid, not by luck.
      profiles.holdFetch!.complete();
      profiles.holdFetch = null;
      final settled = await engine.ready;

      expect(settled.profile?.uid, 'user-2');
      expect(settled.gate, AuthGate.onboarding);
    });

    test('a live push for someone else never lands', () async {
      identity.emit(account);
      await engine.ready;

      profiles.push(const Profile(uid: 'intruder', stage: AccountStage.active));
      await pump();

      expect(engine.status.profile?.uid, uid);
    });

    test('a live push after sign-out cannot resurrect the profile', () async {
      identity.emit(account);
      await engine.ready;

      await engine.signOut();
      await pump();

      profiles.push(active);
      await pump();

      expect(engine.status.profile, isNull);
    });
  });

  group('sign-out', () {
    test('one sign-out, one anonymous replacement, no login flash', () async {
      identity.emit(account);
      await engine.ready;

      final gates = <AuthGate>[];
      final sub = engine.changes.listen((status) => gates.add(status.gate));

      await engine.signOut();
      await pump();
      await sub.cancel();

      expect(identity.calls, ['end', 'anonymous'], reason: 'exactly one of each, in order');
      expect(engine.status.gate, AuthGate.anonymous);
      //* The first recorded gate may still be `ready` — that is runFlow's
      //* bracket publish, before anything is torn down. The property that
      //* matters: once teardown starts (first `loading`), the stale account
      //* view never reappears, and the gap renders as the loader — never as a
      //* flash of the login screen.
      final teardown = gates.indexOf(AuthGate.loading);
      expect(teardown, isNot(-1));
      expect(gates.sublist(teardown), isNot(contains(AuthGate.ready)));
      expect(gates.last, AuthGate.anonymous);
    });

    test('a NoneSession during any flow is the flow\'s business, not the supervisor\'s', () async {
      identity.emit(account);
      await engine.ready;

      await engine.runFlow<void>(() async {
        identity.emit(const NoneSession());
        await pump();
        expect(identity.calls, isEmpty, reason: 'mid-flow: the gap belongs to the flow');
      });
      await pump();

      expect(identity.calls, ['anonymous'], reason: 'the last bracket down re-checks');
    });
  });

  group('flows and recovery', () {
    test('a cancelled flow surfaces and retry clears it', () async {
      identity.emit(const NoneSession());
      await engine.ready;

      final result = await engine.runFlow<String>(() async {
        throw const AuthFlowException(AuthIssue.cancelled);
      });

      expect(result, isNull);
      expect(engine.status.gate, AuthGate.failed);
      expect(engine.status.issue, AuthIssue.cancelled);

      engine.retry();
      await pump();

      expect(engine.status.gate, AuthGate.anonymous, reason: 'the session was fine all along');
    });

    test('a failed anonymous sign-in surfaces, does not loop, and retries', () async {
      identity
        ..autoEmitGuest = false
        ..anonymousError = const AuthFlowException(AuthIssue.network);

      identity.emit(const NoneSession());
      final settled = await engine.ready;
      await pump();

      expect(settled.gate, AuthGate.failed);
      expect(identity.calls, ['anonymous'], reason: 'one attempt, no retry storm');

      //* Network returns; the user taps retry.
      identity
        ..anonymousError = null
        ..autoEmitGuest = true;
      engine.retry();
      await pump();

      expect(engine.status.gate, AuthGate.anonymous);
      expect(identity.calls, ['anonymous', 'anonymous']);
    });

    test('an account profile failure retries into ready', () async {
      profiles.fetchError = const AuthFlowException(AuthIssue.network);
      identity.emit(account);
      await engine.ready;

      profiles.fetchError = null;
      engine.retry();
      await pump();

      expect(engine.status.gate, AuthGate.ready);
    });
  });

  group('session churn', () {
    test('a same-identity update keeps the profile and skips the refetch', () async {
      //* Token refreshes and verification reloads re-emit the same user.
      //* Re-fetching on each would flicker the app through `loading` on every
      //* provider tick.
      const unverified = AccountSession(uid: uid, email: 'a@b.com', mustVerifyEmail: true, emailVerified: false);
      identity.emit(unverified);
      await pump();

      //* Unverified email is a nudge, not a gate: the profile decides.
      expect(engine.status.gate, AuthGate.ready);
      expect(engine.status.needsEmailVerification, isTrue);

      identity.emit(const AccountSession(uid: uid, email: 'a@b.com', mustVerifyEmail: true, emailVerified: true));
      await pump();

      expect(engine.status.gate, AuthGate.ready);
      expect(engine.status.needsEmailVerification, isFalse);
      expect(profiles.fetched, [uid], reason: 'one fetch across both emissions');
    });

    test('a guest upgrading to an account re-reads and lands in onboarding', () async {
      //* Linking keeps the uid; the document still says guest until promotion
      //* lands. Same uid, different session KIND — a fresh identity.
      profiles.store[uid] = const Profile(uid: uid, stage: AccountStage.guest);
      identity.emit(const GuestSession(uid: uid));
      await engine.ready;

      identity.emit(account);
      await pump();

      expect(engine.status.gate, AuthGate.onboarding);
      expect(profiles.fetched, [uid, uid], reason: 'the upgrade re-reads the document');
    });

    test('a sign-out landing mid-round gets a fresh guest, not a spinner', () async {
      //* The anonymous round stays open past the session landing (the
      //* guest-doc ensure call). A sign-out inside that window is refused by
      //* the one-in-flight guard, and no provider tick follows to answer it —
      //* the round's completion must.
      identity.holdAnonymous = Completer<void>();
      identity.emit(const NoneSession());
      await pump();
      expect(engine.status.gate, AuthGate.anonymous);

      await engine.signOut();
      await pump();
      expect(engine.status.gate, AuthGate.loading);
      expect(identity.calls, ['anonymous', 'end'], reason: 'the guard refused a second round');

      identity.holdAnonymous!.complete();
      identity.holdAnonymous = null;
      await pump();

      expect(identity.calls, ['anonymous', 'end', 'anonymous']);
      expect(engine.status.gate, AuthGate.anonymous);
      expect(engine.status.session.uid, 'guest-2');
    });

    test('a guest whose event came before the sign-out\'s is adopted, not waited for', () async {
      //* Android, sign-out mid-round: the provider ends up holding the guest,
      //* but its NoneSession is delivered AFTER the guest's event. The next
      //* anonymous sign-in returns that same guest and emits nothing.
      identity.holdAnonymous = Completer<void>();
      identity.emit(const NoneSession());
      await pump();
      expect(engine.status.session.uid, 'guest-1');

      identity.emit(const NoneSession());
      identity.current = const GuestSession(uid: 'guest-1');
      await pump();
      expect(engine.status.gate, AuthGate.loading);

      identity.holdAnonymous!.complete();
      identity.holdAnonymous = null;
      await pump();

      expect(identity.calls, ['anonymous', 'anonymous']);
      expect(engine.status.gate, AuthGate.anonymous);
      expect(engine.status.session.uid, 'guest-1');
    });

    group('a finished round that left no session', () {
      //* Android release gate, 2026-11-25: a sign-out landed while the guest
      //* sign-in was in flight. The round ended "created", no guest ever came
      //* down the stream, no sign-out event followed, and the device rested
      //* on `loading` for good.
      late FakeIdentity lostIdentity;
      late AuthEngine lostEngine;

      setUp(() {
        lostIdentity = FakeIdentity()..autoEmitGuest = false;
        lostEngine = AuthEngine(
          identity: lostIdentity,
          profiles: profiles,
          profileRetryDelay: Duration.zero,
          guestArrivalGrace: const Duration(milliseconds: 20),
        )..start();
      });

      tearDown(() async {
        await lostEngine.dispose();
        await lostIdentity.close();
      });

      Future<void> grace() => Future<void>.delayed(const Duration(milliseconds: 40));

      test('is looked at again and gets a guest', () async {
        lostIdentity.emit(const NoneSession());
        await pump();
        expect(lostEngine.status.gate, AuthGate.loading);
        expect(lostIdentity.calls, ['anonymous']);

        lostIdentity.autoEmitGuest = true;
        await grace();

        expect(lostIdentity.calls, ['anonymous', 'anonymous']);
        expect(lostEngine.status.gate, AuthGate.anonymous);
      });

      test('adopts the guest the provider holds when its event was lost', () async {
        lostIdentity.emit(const NoneSession());
        await pump();
        lostIdentity.current = const GuestSession(uid: 'held');
        await grace();

        expect(lostEngine.status.gate, AuthGate.anonymous);
        expect(lostEngine.status.session.uid, 'held');
      });

      test('shows the retry screen after three empty rounds, not a spinner', () async {
        lostIdentity.emit(const NoneSession());
        await Future<void>.delayed(const Duration(milliseconds: 200));

        expect(lostIdentity.calls, ['anonymous', 'anonymous', 'anonymous', 'anonymous']);
        expect(lostEngine.status.gate, AuthGate.failed);

        //* The user taps retry: the count starts over.
        lostIdentity.autoEmitGuest = true;
        lostEngine.retry();
        await pump();
        expect(lostEngine.status.gate, AuthGate.anonymous);
      });
    });

    test('a round that outlives its own guest landing does not double-sign-in', () async {
      identity.holdAnonymous = Completer<void>();
      identity.emit(const NoneSession());
      await pump();

      identity.holdAnonymous!.complete();
      identity.holdAnonymous = null;
      await pump();

      expect(identity.calls, ['anonymous'], reason: 'no sign-out landed, nothing to answer');
      expect(engine.status.session.uid, 'guest-1');
    });
  });

  group('impersonation — ordinary session changes', () {
    //* The engine has no impersonate() method, and that is the design: a
    //* minted target session arrives through the provider stream like any
    //* other sign-in, and the return trip is the same in reverse. These tests
    //* pin that the ordinary machinery really does carry the whole feature.
    const minted = AccountSession(uid: 'user-2', impersonatedBy: uid);

    test('a minted session resolves as the target, claim intact', () async {
      profiles.store['user-2'] = const Profile(uid: 'user-2', stage: AccountStage.disabled);
      identity.emit(account);
      await engine.ready;

      identity.emit(minted);
      await pump();

      expect(engine.status.isImpersonating, isTrue);
      expect(engine.status.impersonatedBy, uid);
      expect(engine.status.gate, AuthGate.disabled, reason: 'the admin sees exactly what the target sees');
      expect(profiles.fetched, [uid, 'user-2'], reason: "the TARGET's document is followed");
    });

    test('returning lands on the admin\'s CURRENT profile, freshly read', () async {
      profiles.store['user-2'] = const Profile(uid: 'user-2', stage: AccountStage.active);
      identity.emit(account);
      await engine.ready;

      identity.emit(minted);
      await pump();

      //* The admin's document changes while they are away.
      profiles.store[uid] = const Profile(uid: uid, stage: AccountStage.onboarding);

      identity.emit(account);
      await pump();

      expect(engine.status.isImpersonating, isFalse);
      expect(engine.status.gate, AuthGate.onboarding, reason: 'a fresh read, not a stale snapshot');
    });

    test('an app restart mid-impersonation still knows', () async {
      //* The claim lives in the ID token, so the restored session carries it.
      //* An in-memory overlay would forget — and leave the admin silently
      //* wearing someone else's account.
      profiles.store['user-2'] = const Profile(uid: 'user-2', stage: AccountStage.active);

      identity.emit(minted); // first emission after relaunch: the restored session

      final settled = await engine.ready;

      expect(settled.isImpersonating, isTrue);
      expect(settled.impersonatedBy, uid);
    });
  });

  group('coverage the sibling design pins — matched here', () {
    test('nested flows keep the supervisor suppressed until the LAST one ends', () async {
      identity.emit(account);
      await engine.ready;

      final first = Completer<void>();
      final second = Completer<void>();
      final flowA = engine.runFlow<void>(() => first.future);
      final flowB = engine.runFlow<void>(() => second.future);
      await pump();

      identity.emit(const NoneSession());
      await pump();
      expect(identity.calls, isEmpty, reason: 'two brackets up');

      first.complete();
      await flowA;
      await pump();
      expect(identity.calls, isEmpty, reason: 'one bracket still up');

      second.complete();
      await flowB;
      await pump();
      expect(identity.calls, ['anonymous'], reason: 'the last bracket down re-checks, once');
    });

    test('a session arriving on the stream also recovers — retry is not the only door', () async {
      //* The provider can hand back a session without the app asking (a
      //* background token restore, a second attempt succeeding late). A
      //* surfaced failure must not hold the gate hostage when the underlying
      //* problem has already resolved itself.
      identity
        ..autoEmitGuest = false
        ..anonymousError = const AuthFlowException(AuthIssue.network);
      identity.emit(const NoneSession());
      await engine.ready;

      expect(engine.status.gate, AuthGate.failed);

      identity.emit(const GuestSession(uid: 'guest-late'));
      await pump();

      expect(engine.status.gate, AuthGate.anonymous);
      expect(engine.status.issue, isNull, reason: 'a new identity is a fresh slate');
    });

    test('no input leaves a settled machine unsettled for good', () async {
      //* Sweep: from a settled ready state, every input must either leave the
      //* machine settled or kick off work that settles it again (given a
      //* backend that answers). "Unsettled with nothing in flight" is the
      //* stuck-on-splash class of bug.
      //*
      //* Deliberately absent: an account switch to a uid with NO document.
      //* That stays `loading` by design — no timers in the core — and leans on
      //* the live stream plus boot's step timeout (see README).
      Future<void> check(
        String label,
        Future<void> Function(AuthEngine engine, FakeIdentity identity, FakeProfiles profiles) input,
      ) async {
        final localIdentity = FakeIdentity();
        final localProfiles = FakeProfiles()
          ..store[uid] = active
          ..store['user-2'] = const Profile(uid: 'user-2', stage: AccountStage.active);
        final localEngine = AuthEngine(identity: localIdentity, profiles: localProfiles, profileRetryDelay: Duration.zero)..start();

        localIdentity.emit(account);
        await localEngine.ready;

        await input(localEngine, localIdentity, localProfiles);
        await pump(8);

        expect(localEngine.status.settled, isTrue, reason: '"$label" left the machine unsettled');

        await localEngine.dispose();
        await localIdentity.close();
        await localProfiles.close();
      }

      await check('provider drops the session', (_, identity, _) async => identity.emit(const NoneSession()));
      await check('provider swaps to a guest', (_, identity, _) async => identity.emit(const GuestSession(uid: 'g9')));
      await check('provider switches accounts', (_, identity, _) async {
        identity.emit(const AccountSession(uid: 'user-2'));
      });
      await check('a live profile change lands', (_, _, profiles) async {
        profiles.push(const Profile(uid: uid, stage: AccountStage.disabled));
      });
      await check('sign out', (engine, _, _) => engine.signOut());
      await check('a flow fails', (engine, _, _) async {
        await engine.runFlow<void>(() async => throw const AuthFlowException(AuthIssue.cancelled));
      });
      await check('retry after a failed flow', (engine, _, _) async {
        await engine.runFlow<void>(() async => throw const AuthFlowException(AuthIssue.network));
        engine.retry();
      });
      await check('a minted impersonation session arrives', (_, identity, _) async {
        identity.emit(const AccountSession(uid: 'user-2', impersonatedBy: uid));
      });
    });
  });
  group('emission traces — what the user SEES between rest states', () {
    //* The settle-state tests above prove where the machine ends up; none of
    //* them could see a 200ms `failed` emission mid-login — which is exactly
    //* what shipped as the "Try again" flash. These record every gate the
    //* engine publishes and pin the whole trace, so a transient wrong state
    //* fails the suite even when the end state is correct.

    List<AuthGate> collapse(List<AuthGate> gates) {
      final out = <AuthGate>[];
      for (final gate in gates) {
        if (out.isEmpty || out.last != gate) out.add(gate);
      }
      return out;
    }

    test('a healthy guest-to-account login never emits failed', () async {
      final localIdentity = FakeIdentity();
      final localProfiles = FakeProfiles()..store[uid] = active;
      final localEngine = AuthEngine(
        identity: localIdentity,
        profiles: localProfiles,
        profileRetryDelay: const Duration(milliseconds: 60),
      )..start();
      addTearDown(localEngine.dispose);
      addTearDown(localIdentity.close);
      addTearDown(localProfiles.close);

      localIdentity.emit(const GuestSession(uid: 'guest-1'));
      await pump();

      final trace = <AuthGate>[];
      final sub = localEngine.changes.listen((status) => trace.add(status.gate));
      addTearDown(sub.cancel);

      await localEngine.runFlow(() async {
        localIdentity.emit(account);
        await pump();
      });
      await pump();

      expect(trace, isNot(contains(AuthGate.failed)));
      expect(collapse(trace).last, AuthGate.ready);
    });

    test('a login whose FIRST profile read fails still never emits failed', () async {
      //* The shipped flash, as a frame-level pin: one lost fetch, stream
      //* delivers a beat later. The trace must go loading -> ready with no
      //* failed emission anywhere.
      final localIdentity = FakeIdentity();
      final localProfiles = FakeProfiles();
      final localEngine = AuthEngine(
        identity: localIdentity,
        profiles: localProfiles,
        profileRetryDelay: const Duration(milliseconds: 60),
      )..start();
      addTearDown(localEngine.dispose);
      addTearDown(localIdentity.close);
      addTearDown(localProfiles.close);

      localIdentity.emit(const GuestSession(uid: 'guest-1'));
      await pump();

      final trace = <AuthGate>[];
      final sub = localEngine.changes.listen((status) => trace.add(status.gate));
      addTearDown(sub.cancel);

      localProfiles.fetchError = const AuthFlowException(AuthIssue.network);
      await localEngine.runFlow(() async {
        localIdentity.emit(account);
        await pump();
      });
      localProfiles.push(active);
      await pump();
      //* Let the scheduled retries fire into the delivered profile: still no-op.
      await Future<void>.delayed(const Duration(milliseconds: 200));

      expect(trace, isNot(contains(AuthGate.failed)));
      expect(collapse(trace).last, AuthGate.ready);
    });

    test('sign-out to guest replacement never emits failed or a login flash', () async {
      final localIdentity = FakeIdentity();
      final localProfiles = FakeProfiles()..store[uid] = active;
      final localEngine = AuthEngine(
        identity: localIdentity,
        profiles: localProfiles,
        profileRetryDelay: Duration.zero,
      )..start();
      addTearDown(localEngine.dispose);
      addTearDown(localIdentity.close);
      addTearDown(localProfiles.close);

      localIdentity.emit(account);
      await localEngine.ready;
      await pump();

      final trace = <AuthGate>[];
      final sub = localEngine.changes.listen((status) => trace.add(status.gate));
      addTearDown(sub.cancel);

      await localEngine.signOut();
      await pump();

      expect(trace, isNot(contains(AuthGate.failed)));
      //* The leading `ready` is the busyFlows bump re-publishing the still-
      //* loaded status (the FLOWS layer renders that instant as loading via
      //* its own flowLoader). After it: LOADING while the session swaps, then
      //* the guest — an emitted `anonymous` before the replacement session
      //* lands would flash the guest banner; anything else is the wrong
      //* screen entirely.
      expect(
        collapse(trace),
        [AuthGate.ready, AuthGate.loading, AuthGate.anonymous],
        reason: 'ready (flow bracket) -> loading while swapping -> guest, nothing else',
      );
    });

    test('a genuinely dead profile backend DOES emit failed — the pin cuts both ways', () async {
      //* Guards the guard: if someone "fixes" flakes by swallowing failures
      //* entirely, this trace loses its failed emission and the suite says so.
      final localIdentity = FakeIdentity();
      final localProfiles = FakeProfiles()..fetchError = const AuthFlowException(AuthIssue.network);
      final localEngine = AuthEngine(
        identity: localIdentity,
        profiles: localProfiles,
        profileRetryDelay: Duration.zero,
      )..start();
      addTearDown(localEngine.dispose);
      addTearDown(localIdentity.close);
      addTearDown(localProfiles.close);

      final trace = <AuthGate>[];
      final sub = localEngine.changes.listen((status) => trace.add(status.gate));
      addTearDown(sub.cancel);

      localIdentity.emit(account);
      await localEngine.ready;

      expect(collapse(trace).last, AuthGate.failed);
    });
  });

  group('guest document repair', () {
    test('a guest whose document never landed gets one more ensure after the round, and on the next tick', () async {
      //* Both ensure attempts inside the round failed silently (the round
      //* itself does not throw on a missing doc) — the install used to rest
      //* here with a working-looking app and a permanently empty deck.
      profiles.store.clear();
      identity.emit(const NoneSession());
      await engine.ready;
      expect(identity.calls, ['anonymous']);

      //* The scheduled repair runs after kGuestDocRepairDelay; fake time is
      //* not available here, so drive the same path through a provider tick.
      identity.emit(GuestSession(uid: engine.status.session.uid!));
      await pump();
      expect(identity.calls, contains('ensureGuestDoc'));
    });

    test('no repair once the document exists', () async {
      identity.emit(const NoneSession());
      final settled = await engine.ready;
      profiles.store[settled.session.uid!] = Profile(uid: settled.session.uid!, stage: AccountStage.guest);
      profiles.push(Profile(uid: settled.session.uid!, stage: AccountStage.guest));
      await pump();

      identity.emit(GuestSession(uid: settled.session.uid!));
      await pump();
      expect(identity.calls, isNot(contains('ensureGuestDoc')));
    });
  });
}
