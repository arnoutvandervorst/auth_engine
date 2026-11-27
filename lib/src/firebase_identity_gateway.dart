import 'dart:async';

import 'package:firebase_auth/firebase_auth.dart' as fb;
import 'package:auth_engine/src/auth_gateways.dart';
import 'package:auth_engine/src/auth_status.dart';

/// How long a session's ID-token read may take before the session goes on
/// without its claims ([FirebaseIdentityGateway.impersonationClaim]).
const kTokenReadTimeout = Duration(seconds: 5);

/// The Firebase edge of identity: the only file here that imports an SDK;
/// everything above it works on plain values. What belongs to one app comes
/// in as a function: [ensureGuestDoc] asks that app's backend for the guest
/// document, [onAnonymousSignInFailed] reports to that app's failure log.

/// Whether [user] has an e-mail address the app must prove. Only a password
/// account has one: Google and Apple verified theirs. The one rule the
/// session and the auth service both answer from.
bool mustVerifyEmail(fb.User user) {
  final providers = user.providerData.map((info) => info.providerId).toSet();
  return user.email != null && providers.contains('password') && !providers.contains('google.com') && !providers.contains('apple.com');
}

class FirebaseIdentityGateway implements IdentityGateway {
  final fb.FirebaseAuth _auth;
  final Future<void> Function() _ensureGuestDoc;
  final void Function(Object error)? _onAnonymousSignInFailed;

  FirebaseIdentityGateway({
    fb.FirebaseAuth? auth,
    required this._ensureGuestDoc,
    this._onAnonymousSignInFailed,
  }) : _auth = auth ?? fb.FirebaseAuth.instance;

  @override
  //* `userChanges`, not `authStateChanges`. Linking a phone or reloading after
  //* email verification mutates the SAME provider user without a sign-in edge,
  //* and both change facts the gate reads — `authStateChanges` stays silent
  //* for those and the gate would keep answering from stale evidence. Repeat
  //* emissions of an unchanged user are cheap: the engine's same-identity path
  //* is a field update with no re-fetch.
  //*
  //* `asyncMap` because the impersonation claim lives in the ID token, which
  //* is an async read (cached — no network unless the token is stale). It
  //* also serialises emissions, so enrichment cannot reorder sessions.
  Stream<Session> get changes => _auth.userChanges().asyncMap(_enrich);

  @override
  Session get current => sessionOf(_auth.currentUser);

  Future<Session> _enrich(fb.User? user) async {
    if (user == null || user.isAnonymous) return sessionOf(user);

    //* The claim travels in the ID token because the impersonation endpoint
    //* mints the custom token with it — which is what lets Firestore RULES see
    //* impersonation too, not just the client.
    return sessionOf(user, impersonatedBy: await impersonationClaim(() async => (await user.getIdTokenResult()).claims));
  }

  /// The `impersonatedBy` claim from [readClaims], or null when the read
  /// fails or takes longer than [timeout].
  ///
  //* `asyncMap` serialises emissions, so a token read that never returns
  //* holds back every session after it — including the guest that follows a
  //* sign-out, and the device rests on `loading`. A token-less session carries no impersonation claim;
  //* the next provider tick (token refresh) carries it if it was there.
  static Future<String?> impersonationClaim(
    Future<Map<String, dynamic>?> Function() readClaims, {
    Duration timeout = kTokenReadTimeout,
  }) async {
    try {
      return (await readClaims().timeout(timeout))?['impersonatedBy'] as String?;
    } on fb.FirebaseAuthException {
      //* The user signed out (or switched) between this emission and the
      //* token read — `no-current-user`. The sign-out's own emission follows;
      //* an uncaught error here escaped the stream as an unhandled crash
      //* (found by the Android release gate).
      return null;
    } on TimeoutException {
      return null;
    }
  }

  /// Whether the guest this side still shows is one the SDK still holds.
  ///
  //* A sign-out that lands while an anonymous sign-in is in flight leaves the
  //* Dart side showing a guest the native SDK already signed out (found by
  //* an Android release gate, 2026-11-25): its token read answers `no-current-user`.
  //* Adopting that guest would give an app that looks signed in and is
  //* refused by every rule. Any other answer (a token, a network error, a
  //* slow read) leaves the guest in place.
  static Future<bool> guestStillHeld(
    Future<String?> Function() readToken, {
    Duration timeout = kTokenReadTimeout,
  }) async {
    try {
      await readToken().timeout(timeout);
      return true;
    } on fb.FirebaseAuthException catch (error) {
      return error.code != 'no-current-user';
    } on TimeoutException {
      return true;
    }
  }

  @override
  Future<bool> ensureAnonymousSession() async {
    //* Already a guest (its event raced a sign-out's): a sign-in would return
    //* this same user and emit nothing. The engine adopts it from [current].
    final held = _auth.currentUser;
    if (held != null && held.isAnonymous && await guestStillHeld(held.getIdToken)) return false;
    try {
      await _auth.signInAnonymously();
    } catch (error) {
      //* No Firebase user exists yet: the one failure only the device sees
      //* (the engine turns it into a generic retry screen).
      _onAnonymousSignInFailed?.call(error);
      rethrow;
    }

    //* Ask the backend to create the guest /users doc now, so it exists
    //* deterministically when boot continues (gen-2 replacement for the
    //* retired v1 auth trigger). Best-effort with one retry + Crashlytics on
    //* final failure; the profile gateway treats an absent guest doc as
    //* routine, and the signup path creates it if it is still missing.
    await _ensureGuestDoc();
    return true;
  }

  @override
  Future<void> ensureGuestDoc() => _ensureGuestDoc();

  @override
  Future<void> endSession() => _auth.signOut();

  /// Projects a provider user onto the facts the engine reads. Static and
  /// pure so the projection logic is testable — though `fb.User` itself
  /// cannot be constructed outside the SDK, which is exactly why everything
  /// downstream works on [Session] instead.
  static Session sessionOf(fb.User? user, {String? impersonatedBy}) {
    if (user == null) return const NoneSession();
    if (user.isAnonymous) return GuestSession(uid: user.uid);

    final phone = user.phoneNumber;

    return AccountSession(
      uid: user.uid,
      impersonatedBy: impersonatedBy,
      email: user.email,
      emailVerified: user.emailVerified,
      mustVerifyEmail: mustVerifyEmail(user),
      verifiedPhone: (phone == null || phone.isEmpty) ? null : phone,
    );
  }
}
