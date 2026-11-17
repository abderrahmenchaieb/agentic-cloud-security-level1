from __future__ import annotations
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional
import uuid

from .sequence_schema import Event, Sequence, EventCategory


@dataclass
class SequenceBuilderConfig:
    time_window_seconds: float = 300.0
    # PAR DÉFAUT False : filiation stricte (séquences propres).
    # À activer pour rattraper les attaques qui CASSENT la filiation.
    merge_by_session: bool = False
    merge_orphans_by_host: bool = True


class SequenceBuilder:
    def __init__(self, config: Optional[SequenceBuilderConfig] = None):
        self.config = config or SequenceBuilderConfig()

    def build(self, events: list[Event]) -> list[Sequence]:
        events = sorted(events, key=lambda e: e.event_time)
        guid_to_group: dict[str, str] = {}
        groups: dict[str, list[Event]] = {}

        def new_group() -> str:
            gid = f"seq-{uuid.uuid4().hex[:8]}"
            groups[gid] = []
            return gid

        for e in events:
            group_id = None
            if e.process_guid:
                if e.process_guid in guid_to_group:
                    group_id = guid_to_group[e.process_guid]
                elif e.parent_process_guid and e.parent_process_guid in guid_to_group:
                    group_id = guid_to_group[e.parent_process_guid]
                    guid_to_group[e.process_guid] = group_id
                else:
                    group_id = new_group()
                    guid_to_group[e.process_guid] = group_id
            else:
                group_id = None
            if group_id is not None:
                groups[group_id].append(e)
            else:
                groups.setdefault("__orphans__", []).append(e)

        orphans = groups.pop("__orphans__", [])
        if orphans and self.config.merge_orphans_by_host:
            for e in orphans:
                gid = self._find_group_by_host_time(e, groups)
                if gid is None:
                    gid = new_group()
                groups[gid].append(e)
        elif orphans:
            for e in orphans:
                gid = new_group()
                groups[gid].append(e)

        if self.config.merge_by_session:
            groups = self._merge_by_session(groups)

        sequences: list[Sequence] = []
        for gid, evs in groups.items():
            if not evs:
                continue
            sequences.extend(self._split_by_time_window(evs))
        return sequences

    def _find_group_by_host_time(self, event: Event, groups: dict[str, list[Event]]) -> Optional[str]:
        window = self.config.time_window_seconds
        for gid, evs in groups.items():
            for e in evs:
                if e.host == event.host and abs((e.event_time - event.event_time).total_seconds()) <= window:
                    return gid
        return None

    def _merge_by_session(self, groups: dict[str, list[Event]]) -> dict[str, list[Event]]:
        session_to_group: dict[str, str] = {}
        merged: dict[str, list[Event]] = {}
        remap: dict[str, str] = {}
        for gid, evs in groups.items():
            session_key = None
            for e in evs:
                if e.session_id:
                    session_key = f"{e.host}:{e.session_id}"
                    break
            if session_key and session_key in session_to_group:
                remap[gid] = session_to_group[session_key]
            else:
                merged[gid] = list(evs)
                if session_key:
                    session_to_group[session_key] = gid
        for gid, target in remap.items():
            merged[target].extend(groups[gid])
        return merged

    def _split_by_time_window(self, events: list[Event]) -> list[Sequence]:
        events = sorted(events, key=lambda e: e.event_time)
        window = self.config.time_window_seconds
        sequences: list[Sequence] = []
        current: list[Event] = []
        for e in events:
            if not current:
                current = [e]
                continue
            gap = (e.event_time - current[-1].event_time).total_seconds()
            if gap > window:
                sequences.append(self._make_sequence(current))
                current = [e]
            else:
                current.append(e)
        if current:
            sequences.append(self._make_sequence(current))
        return sequences

    def _make_sequence(self, events: list[Event]) -> Sequence:
        events = sorted(events, key=lambda e: e.event_time)
        guids = {e.process_guid for e in events if e.process_guid}
        root = None
        for e in events:
            if e.process_guid and (not e.parent_process_guid or e.parent_process_guid not in guids):
                root = e.process_guid
                break
        return Sequence(
            sequence_id=f"seq-{uuid.uuid4().hex[:8]}",
            events=events, host=events[0].host, root_process_guid=root,
        )
