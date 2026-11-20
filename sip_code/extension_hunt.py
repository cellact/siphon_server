"""Siphon-local Light PBX seat occupancy and hunt FIFO.

Blind: only honors optional `isExtension` / `productItemId` on route targets.
No config lookup. In-process, one siphon process.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Optional


def _log(msg: str) -> None:
    try:
        from siphon import log  # type: ignore

        log.info(msg)
    except Exception:  # noqa: BLE001
        print(f"[extension_hunt] {msg}", flush=True)


def seat_id(target: dict[str, Any]) -> str:
    return str(target.get("productItemId") or target.get("notifyIdentity") or "").strip()


def has_extension(targets: list[dict[str, Any]]) -> bool:
    return any(bool(t.get("isExtension")) and seat_id(t) for t in targets or [])


def hunt_key(targets: list[dict[str, Any]]) -> str:
    ids = sorted({seat_id(t) for t in targets or [] if t.get("isExtension") and seat_id(t)})
    if not ids:
        return ""
    if len(ids) == 1:
        return ids[0]
    return ",".join(ids)


def describe_targets(targets: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for t in targets or []:
        ident = str(t.get("notifyIdentity") or "")
        seat = seat_id(t)
        flag = bool(t.get("isExtension"))
        parts.append(f"{ident or '-'} isExtension={flag} seat={seat or '-'}")
    return "; ".join(parts) if parts else "-"


class Occupancy:
    def __init__(self) -> None:
        self._seat_to_session: dict[str, str] = {}

    def owner(self, seat: str) -> str:
        return self._seat_to_session.get(seat, "")

    def busy(self, seat: str, except_session: str = "") -> bool:
        owner = self._seat_to_session.get(seat)
        if not owner:
            return False
        if except_session and owner == except_session:
            return False
        return True

    def set(self, seat: str, session_id: str) -> None:
        if not seat or not session_id:
            return
        prev = self._seat_to_session.get(seat)
        self._seat_to_session[seat] = session_id
        if prev and prev != session_id:
            _log(
                f"HUNT/OCCUPANCY: update seat={seat} session={session_id} "
                f"was={prev}"
            )
        elif prev == session_id:
            _log(f"HUNT/OCCUPANCY: keep seat={seat} session={session_id}")
        else:
            _log(f"HUNT/OCCUPANCY: set seat={seat} session={session_id}")

    def clear_seat(self, seat: str, session_id: str = "") -> bool:
        owner = self._seat_to_session.get(seat)
        if not owner:
            return False
        if session_id and owner != session_id:
            return False
        self._seat_to_session.pop(seat, None)
        _log(
            f"HUNT/OCCUPANCY: clear seat={seat} freedBy={session_id or owner} "
            f"was={owner}"
        )
        return True

    def clear_session(self, session_id: str) -> list[str]:
        if not session_id:
            return []
        freed = [s for s, sid in self._seat_to_session.items() if sid == session_id]
        for seat in freed:
            self._seat_to_session.pop(seat, None)
            _log(f"HUNT/OCCUPANCY: clear seat={seat} session={session_id}")
        return freed


class _Waiter:
    __slots__ = ("session_id", "seat_ids", "enqueued_at")

    def __init__(self, session_id: str, seat_ids: set[str], enqueued_at: float) -> None:
        self.session_id = session_id
        self.seat_ids = seat_ids
        self.enqueued_at = enqueued_at


class HuntQueue:
    def __init__(self) -> None:
        self._queues: dict[str, deque[_Waiter]] = {}

    def _recompute(self, key: str, sessions: dict[str, dict[str, Any]]) -> None:
        dq = self._queues.get(key)
        if not dq:
            return
        for i, waiter in enumerate(dq):
            sess = sessions.get(waiter.session_id)
            if sess is not None:
                sess["queuePosition"] = i + 1

    def enqueue(
        self,
        key: str,
        session: dict[str, Any],
        seat_ids: set[str],
        sessions: dict[str, dict[str, Any]],
    ) -> None:
        sid = str(session.get("workerSessionId") or session.get("sessionId") or "")
        if not key or not sid:
            return
        dq = self._queues.setdefault(key, deque())
        for waiter in dq:
            if waiter.session_id == sid:
                self._recompute(key, sessions)
                return
        dq.append(_Waiter(sid, set(seat_ids), time.monotonic()))
        self._recompute(key, sessions)

    def remove(self, session_id: str, sessions: dict[str, dict[str, Any]]) -> None:
        if not session_id:
            return
        empty: list[str] = []
        for key, dq in self._queues.items():
            kept = deque(w for w in dq if w.session_id != session_id)
            if len(kept) != len(dq):
                if kept:
                    self._queues[key] = kept
                    self._recompute(key, sessions)
                else:
                    empty.append(key)
        for key in empty:
            self._queues.pop(key, None)
        sess = sessions.get(session_id)
        if sess is not None:
            sess["queuePosition"] = None

    def pop_eligible(self, seat_id: str, occupancy: Occupancy) -> Optional[_Waiter]:
        if not seat_id:
            return None
        best: Optional[_Waiter] = None
        best_key = ""
        for key, dq in self._queues.items():
            for waiter in dq:
                if seat_id not in waiter.seat_ids:
                    continue
                if not any(not occupancy.busy(s) for s in waiter.seat_ids):
                    continue
                if best is None or waiter.enqueued_at < best.enqueued_at:
                    best = waiter
                    best_key = key
                break
        if best is None or not best_key:
            return None
        dq = self._queues.get(best_key)
        if dq is None:
            return None
        self._queues[best_key] = deque(w for w in dq if w.session_id != best.session_id)
        if not self._queues[best_key]:
            self._queues.pop(best_key, None)
        _log(
            f"HUNT: dequeue waiter session={best.session_id} freedSeat={seat_id} "
            f"key={best_key}"
        )
        return best


class ExtensionHuntPolicy:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.occupancy = Occupancy()
        self.queue = HuntQueue()

    def filter_and_maybe_enqueue(
        self,
        targets: list[dict[str, Any]],
        session: dict[str, Any],
        sessions: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not has_extension(targets):
            return list(targets)
        sid = str(session.get("workerSessionId") or session.get("sessionId") or "")
        to_id = str(session.get("to") or "")
        key = hunt_key(targets)
        seat_ids = {seat_id(t) for t in targets if t.get("isExtension") and seat_id(t)}
        with self._lock:
            free: list[dict[str, Any]] = []
            passthrough: list[dict[str, Any]] = []
            skipped: list[str] = []
            for t in targets:
                if not t.get("isExtension"):
                    passthrough.append(t)
                    continue
                seat = seat_id(t)
                if not seat or not self.occupancy.busy(seat, except_session=sid):
                    free.append(t)
                    continue
                owner = self.occupancy.owner(seat)
                skipped.append(f"{seat} owner={owner}")
            if free or passthrough:
                self.queue.remove(sid, sessions)
                session["queuePosition"] = None
                if skipped:
                    _log(
                        f"HUNT: skip busy to={to_id!r} session={sid} "
                        f"busy=[{', '.join(skipped)}] "
                        f"ring={describe_targets(passthrough + free)}"
                    )
                return passthrough + free
            self.queue.enqueue(key, session, seat_ids, sessions)
            pos = session.get("queuePosition")
            _log(
                f"HUNT: queued to={to_id!r} session={sid} key={key} "
                f"position={pos} busy=[{', '.join(skipped)}] "
                f"({describe_targets(targets)})"
            )
            return []

    def mark_ringing(self, session: dict[str, Any], targets: list[dict[str, Any]]) -> None:
        sid = str(session.get("workerSessionId") or session.get("sessionId") or "")
        to_id = str(session.get("to") or "")
        with self._lock:
            for t in targets or []:
                if not t.get("isExtension"):
                    continue
                seat = seat_id(t)
                if seat:
                    ident = str(t.get("notifyIdentity") or seat)
                    _log(
                        f"HUNT: to={ident} is extension — occupy seat={seat} "
                        f"session={sid} dest={to_id!r} state=ringing"
                    )
                    self.occupancy.set(seat, sid)

    def mark_in_call(self, session: dict[str, Any], ident: str) -> None:
        sid = str(session.get("workerSessionId") or session.get("sessionId") or "")
        seat = self._seat_for_ident(session, ident)
        if not seat:
            return
        with self._lock:
            self.occupancy.set(seat, sid)
            _log(f"HUNT/IN-CALL: seat={seat} session={sid} ident={ident}")

    def release_seat(
        self,
        session: dict[str, Any],
        ident: str,
        sessions: dict[str, dict[str, Any]],
    ) -> list[str]:
        sid = str(session.get("workerSessionId") or session.get("sessionId") or "")
        seat = self._seat_for_ident(session, ident)
        pair = str(session.get("sessionId") or "")
        with self._lock:
            cleared = False
            for candidate in (seat, str(ident or "").strip()):
                if candidate and self.occupancy.clear_seat(candidate, sid or pair):
                    cleared = True
                    seat = candidate
            if not cleared:
                return []
            waiter = self.queue.pop_eligible(seat, self.occupancy)
            if waiter:
                self._recompute_waiter_queue(waiter, sessions)
                return [waiter.session_id]
            return []

    def end_session(
        self, session: dict[str, Any], sessions: dict[str, dict[str, Any]]
    ) -> list[str]:
        sid = str(session.get("workerSessionId") or session.get("sessionId") or "")
        with self._lock:
            freed = self.occupancy.clear_session(sid)
            self.queue.remove(sid, sessions)
            wake: list[str] = []
            seen: set[str] = set()
            for seat in freed:
                waiter = self.queue.pop_eligible(seat, self.occupancy)
                if waiter and waiter.session_id not in seen:
                    seen.add(waiter.session_id)
                    self._recompute_waiter_queue(waiter, sessions)
                    wake.append(waiter.session_id)
            return wake

    def _recompute_waiter_queue(
        self, waiter: _Waiter, sessions: dict[str, dict[str, Any]]
    ) -> None:
        sess = sessions.get(waiter.session_id)
        if sess is not None:
            sess["queuePosition"] = None
        for key in self.queue._queues:
            self.queue._recompute(key, sessions)

    @staticmethod
    def _seat_for_ident(session: dict[str, Any], ident: str) -> str:
        ident = str(ident or "")
        for t in list(session.get("huntAllTargets") or []) + list(
            session.get("ringTargets") or []
        ):
            if str(t.get("notifyIdentity") or "") == ident:
                return seat_id(t)
        return ident


policy = ExtensionHuntPolicy()
