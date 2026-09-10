"""
Status lifecycle transition rules, shared by the alert and incident
status-transition endpoints (api/alerts.py, api/incidents.py).

A transition is allowed only if it moves exactly one step forward
through the entity's documented lifecycle order, with one exception:
moving to the lifecycle's first state ("open") is always allowed, to
support reopening an alert or incident from any later state.

Same-status "transitions" are not considered here at all - callers
should check for that separately and reject it as a distinct "already in
that status" error, since it's a different failure mode from an invalid
transition.
"""

ALERT_LIFECYCLE_ORDER = ["open", "acknowledged", "closed"]
INCIDENT_LIFECYCLE_ORDER = ["open", "investigating", "resolved", "closed"]


def is_forward_or_reopen(order: list[str], from_status: str, to_status: str) -> bool:
    """
    True if `to_status` is either the lifecycle's first state (a "reopen",
    allowed from any other state) or exactly the next state after
    `from_status` in `order`. False for same-status, out-of-order jumps,
    and any backward move that isn't a reopen.
    """
    if to_status == order[0]:
        return from_status != to_status

    from_index = order.index(from_status)
    to_index = order.index(to_status)
    return to_index == from_index + 1
