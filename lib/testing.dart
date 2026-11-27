import 'dart:async';

import 'package:auth_engine/src/auth_gateways.dart';
import 'package:auth_engine/src/auth_status.dart';

/// Shared fakes for the auth suites.
///
//* Each is a handful of lines because each gateway asks one question — the
//* narrowness of the seams is what makes them writable at all.
class FakeIdentity implements IdentityGateway {
  final _controller = StreamController<Session>.broadcast();
  final calls = <String>[];

  Object? anonymousError;
  bool autoEmitGuest = true;
  int _guestCounter = 0;

  /// Held open AFTER the guest is emitted — the real gateway keeps the round
  /// open for the guest-doc ensure call long after the session has landed.
  Completer<void>? holdAnonymous;

  @override
  Stream<Session> get changes => _controller.stream;

  /// What the provider holds; [emit] moves it, a test can set it apart from
  /// the stream (an event delivered out of order).
  @override
  Session current = const NoneSession();

  @override
  Future<bool> ensureAnonymousSession() async {
    calls.add('anonymous');
    if (anonymousError != null) throw anonymousError!;
    //* Firebase: an anonymous sign-in while already anonymous returns the same
    //* user and emits nothing.
    if (current is GuestSession) return false;
    if (autoEmitGuest) emit(GuestSession(uid: 'guest-${++_guestCounter}'));
    if (holdAnonymous != null) await holdAnonymous!.future;
    return true;
  }

  @override
  Future<void> endSession() async {
    calls.add('end');
    emit(const NoneSession());
  }

  Object? ensureGuestDocError;

  @override
  Future<void> ensureGuestDoc() async {
    calls.add('ensureGuestDoc');
    if (ensureGuestDocError != null) throw ensureGuestDocError!;
  }

  void emit(Session session) {
    current = session;
    _controller.add(session);
  }

  Future<void> close() => _controller.close();
}

class FakeProfiles implements ProfileGateway {
  final store = <String, Profile>{};
  final fetched = <String>[];
  final watched = <String>[];
  final _live = StreamController<Profile?>.broadcast();

  /// Held open to simulate a slow network, exactly.
  Completer<void>? holdFetch;
  Object? fetchError;

  @override
  Future<Profile?> fetch(String uid) async {
    fetched.add(uid);
    if (holdFetch != null) await holdFetch!.future;
    if (fetchError != null) throw fetchError!;
    return store[uid];
  }

  @override
  //* Deliberately unfiltered: every subscriber sees every push, so the tests
  //* prove the ENGINE keys facts by document uid rather than trusting the
  //* gateway to only deliver relevant ones.
  Stream<Profile?> changes(String uid) {
    watched.add(uid);
    return _live.stream;
  }

  void push(Profile profile) => _live.add(profile);

  /// The live stream reports an error to every subscriber.
  void fail(Object error) => _live.addError(error);

  Future<void> close() => _live.close();
}

Future<void> pump([int rounds = 4]) async {
  for (var i = 0; i < rounds; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}
