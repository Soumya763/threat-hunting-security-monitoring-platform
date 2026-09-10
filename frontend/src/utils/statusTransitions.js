// Mirrors the backend's lifecycle transition rule
// (backend/app/services/status_transitions.py) so the UI only ever offers
// statuses the API will actually accept. Intentionally duplicated rather
// than shared - there's no cross-language sharing mechanism here, and
// the lifecycle arrays are small and stable.
//
// A transition is allowed only if it moves exactly one step forward
// through `order`, with one exception: moving to `order[0]` ("open") is
// always allowed, to support reopening from any later state.

export function getAllowedNextStatuses(order, currentStatus) {
  const allowed = [];

  if (currentStatus !== order[0]) {
    allowed.push(order[0]); // reopen exception
  }

  const currentIndex = order.indexOf(currentStatus);
  if (currentIndex >= 0 && currentIndex < order.length - 1) {
    const nextStep = order[currentIndex + 1];
    if (!allowed.includes(nextStep)) {
      allowed.push(nextStep);
    }
  }

  return allowed;
}
