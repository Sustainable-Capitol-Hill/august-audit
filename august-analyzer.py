#!/usr/bin/env python3

from csv import DictReader
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TypeVar, TypedDict
import sys


# These are the doors at the Capitol Hill Tool Library, but you can replace
# with your own list
class Door(StrEnum):
    FRONT = "Front Door"
    BACK = "Back Door"
    INVENTORY = "Inventory Room"
    BATHROOM = "Bathroom"


class DoorState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class LockState(StrEnum):
    UNLOCKED = "unlocked"
    LOCKED = "locked"


class Event(StrEnum):
    OPENED = "opened"
    CLOSED = "closed"
    UNLOCKED = "unlocked"
    LOCKED = "locked"
    # Can be ignored; indicates someone inputting an incorrect code
    INVALID = "invalid"
    # Changes to the August permissions/codes
    ADDED = "added"
    REMOVED = "removed"
    UPDATED = "updated"
    CHANGED = "changed"


class RawLogRow(TypedDict):
    Time: str
    Action: str
    User: str


class EnrichedLogRow(TypedDict):
    datetime: datetime
    door: Door
    event: Event
    user: str | None


def get_door(text) -> Door:
    for door in Door:
        if door.value in text:
            return door
    else:
        raise ValueError(f'No door name found in "{text}"')


def get_event(text) -> Event:
    for event in Event:
        if event.value in text.lower():
            return event
    else:
        raise ValueError(f'No event name found in "{text}"')


def get_data(filepath: str) -> list[EnrichedLogRow]:
    enriched_rows: list[EnrichedLogRow] = []

    # Download this CSV file by logging into the (really bare bones) August web
    # interface at https://account.august.com/login, and then navigating to "My
    # Data" and requesting a copy of the "Activity Feed"
    with open(filepath) as f:
        rows = DictReader(f)

        for row in rows:
            raw_row: RawLogRow = row
            enriched_row = {
                "datetime": datetime.strptime(
                    raw_row["Time"],
                    r"%a %b %d %Y %H:%M:%S GMT%z (Coordinated Universal Time)",
                ),
                "door": get_door(raw_row["Action"]),
                "event": get_event(raw_row["Action"]),
                "user": raw_row["User"].strip() or None,
            }
            enriched_rows.append(enriched_row)

    return enriched_rows


# Useful for presenting local times in the output; the inputs are timezone-
# aware
def to_local_timezone(dt: datetime) -> datetime:
    return dt.astimezone(tz=None)


def round_hours(td: timedelta) -> int:
    return int(round(td.total_seconds() / 60 / 60, 0))


AuditableState = TypeVar("AuditableState", bound=DoorState | LockState)


def audit(
    data: list[EnrichedLogRow],
    vulnerable_state: AuditableState,
    invulnerable_state: AuditableState,
    vulnerable_event: Event,
    invulnerable_event: Event,
):
    # 3-hour shift plus a 3-hour event seems like a reasonable floor
    warn_if_vulnerable_for_more_than = timedelta(hours=6)

    print(
        f"\nCases when a door was {vulnerable_state.value} for more than {round_hours(warn_if_vulnerable_for_more_than)} hours:\n"
    )

    states: dict[door, AuditableState | None] = dict([(door, None) for door in Door])
    vulnerable_since: dict[door, datetime | None] = dict(
        [(door, None) for door in Door]
    )
    vulnerability_initiated_by: dict[door, str | None] = dict(
        [(door, None) for door in Door]
    )

    # Log is descending chronological order, but we want to analyze it in
    # ascending order
    for row in reversed(data):
        door = row["door"]
        event = row["event"]

        if event == vulnerable_event:
            states[door] = vulnerable_state
            vulnerable_since[door] = row["datetime"]
            vulnerability_initiated_by[door] = row["user"]
        elif event == invulnerable_event:
            if states[door] == vulnerable_state and vulnerable_since[door] is not None:
                vulnerable_duration = row["datetime"] - vulnerable_since[door]
                if vulnerable_duration > warn_if_vulnerable_for_more_than:
                    message = f"Starting on {to_local_timezone(vulnerable_since[door]).strftime(r'%a %b %-d')} at {to_local_timezone(vulnerable_since[door]).strftime(r'%-I:%M %p %Z')}, the {door.value} remained {vulnerable_state.value} for {round_hours(vulnerable_duration)} hours."
                    # August has no way to know who opens/closes doors
                    if isinstance(vulnerable_state, LockState):
                        message += f" It was originally {vulnerable_event.value} by {vulnerability_initiated_by[door] or 'an unidentified user'}."
                    print(f"- {message}")

            states[door] = invulnerable_state
            vulnerable_since[door] = None
            vulnerability_initiated_by[door] = None


if __name__ == "__main__":
    # `activity.csv` is the default name of the August access log file
    filepath = sys.argv[1] if len(sys.argv) > 1 else "activity.csv"
    data = get_data(filepath)
    print(
        f'\nAnalyzing the August access log that covers the past {(data[0]["datetime"] - data[-1]["datetime"]).days} days…'
    )

    audit(
        data,
        vulnerable_state=DoorState.OPEN,
        invulnerable_state=DoorState.CLOSED,
        vulnerable_event=Event.OPENED,
        invulnerable_event=Event.CLOSED,
    )

    audit(
        data,
        vulnerable_state=LockState.UNLOCKED,
        invulnerable_state=LockState.LOCKED,
        vulnerable_event=Event.UNLOCKED,
        invulnerable_event=Event.LOCKED,
    )
