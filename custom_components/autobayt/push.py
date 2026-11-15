"""Push updates: Autobayt posts signed device snapshots to a Home Assistant webhook.

Autobayt keeps one push subscription per account, so every home (config
entry) of the same account shares one webhook here. Each PUT of the
subscription replaces the device list and callback address, returns a new
signing secret and starts a new generation; Autobayt then sends a full
snapshot. Home Assistant subscribes again on every start, so nothing secret is
stored on disk.

A callback is applied only when its HMAC signature matches, its timestamp is
recent, it belongs to the current subscription and generation, and its
sequence is newer than the last one applied. Without a public HTTPS address
for Home Assistant, or when Autobayt refuses the subscription, the homes keep
polling as before and the subscription is tried again later.
"""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime
import hashlib
import hmac
import json
import logging
import time
from typing import TYPE_CHECKING, Any

from aiohttp import web
from yarl import URL

from homeassistant.components import webhook
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.network import NoURLAvailableError
from homeassistant.util import dt as dt_util
from homeassistant.util.hass_dict import HassKey

from .api import AutobaytError
from .const import DOMAIN, PUSH_MAX_CLOCK_SKEW, PUSH_RETRY_INTERVAL

if TYPE_CHECKING:
    from .coordinator import AutobaytDeviceCoordinator

_LOGGER = logging.getLogger(__name__)

PUSH_MANAGERS: HassKey[dict[str, AutobaytPush]] = HassKey(f"{DOMAIN}_push")

SNAPSHOT_TYPE = "device_state_snapshot"
SCHEMA_VERSION = 1


def get_push(hass: HomeAssistant, user_id: str) -> AutobaytPush:
    """Return the push manager of one Autobayt account."""
    managers = hass.data.setdefault(PUSH_MANAGERS, {})
    if user_id not in managers:
        managers[user_id] = AutobaytPush(hass, user_id)
    return managers[user_id]


def callback_url(hass: HomeAssistant, webhook_id: str) -> str:
    """Return the public HTTPS address Autobayt should post to.

    Autobayt only posts to public HTTPS on port 443, so an internal or plain
    HTTP address is no use.
    """
    url = webhook.async_generate_url(
        hass, webhook_id, allow_internal=False, allow_ip=False, prefer_external=True
    )
    parsed = URL(url)
    if parsed.scheme != "https" or parsed.port != 443:
        raise NoURLAvailableError("Home Assistant has no public HTTPS address")
    return url


def signature_ok(secret: str, timestamp: str, body: bytes, signature: str) -> bool:
    """Check an X-Autobayt-Signature header in constant time."""
    if not signature.startswith("sha256="):
        return False
    expected = hmac.new(
        secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature.removeprefix("sha256="))


class AutobaytPush:
    """One webhook subscription for one Autobayt account, shared by its homes."""

    def __init__(self, hass: HomeAssistant, user_id: str) -> None:
        """Create an idle manager."""
        self.hass = hass
        self._user_id = user_id
        self._coordinators: dict[str, AutobaytDeviceCoordinator] = {}
        self._lock = asyncio.Lock()
        self._webhook_id: str | None = None
        self._secret: str | None = None
        self._subscription_id: str | None = None
        self._generation: str | None = None
        self._sequence = 0
        self._seen: deque[str] = deque(maxlen=64)
        self._subscribed: frozenset[str] = frozenset()
        self._next_attempt = 0.0
        self._task: asyncio.Task[None] | None = None
        self.active = False
        self.last_error: str | None = None
        self.last_event: datetime | None = None
        self.events = 0

    # -- membership -------------------------------------------------------

    async def async_add(self, entry_id: str, coordinator: AutobaytDeviceCoordinator) -> None:
        """Add a home and subscribe for its devices too."""
        self._coordinators[entry_id] = coordinator
        coordinator.push = self
        coordinator.set_push_active(self.active)
        await self.async_update(force=True)

    async def async_remove(self, entry_id: str) -> None:
        """Drop a home; stop the subscription when it was the last one."""
        coordinator = self._coordinators.pop(entry_id, None)
        if coordinator is not None:
            coordinator.push = None
        if self._task is not None and not self._task.done():
            self._task.cancel()
        self._task = None
        await self.async_update(force=True, client=coordinator.client if coordinator else None)
        if not self._coordinators:
            self.hass.data.get(PUSH_MANAGERS, {}).pop(self._user_id, None)

    @callback
    def async_check(self) -> None:
        """After a poll: subscribe again if the device list changed or a retry is due."""
        if self._task is not None and not self._task.done():
            return
        if not self.active and time.monotonic() < self._next_attempt:
            return
        # The update only calls Autobayt when the device list differs from
        # the subscription.
        # Not started eagerly: the poll stores its devices first.
        self._task = self.hass.async_create_background_task(
            self.async_update(), "autobayt push subscription", eager_start=False
        )

    def _device_ids(self) -> frozenset[str]:
        ids: set[str] = set()
        for coordinator in self._coordinators.values():
            ids.update(coordinator.data or {})
        return frozenset(ids)

    # -- subscription -----------------------------------------------------

    async def async_update(self, force: bool = False, client: Any = None) -> None:
        """Bring the subscription in line with the homes and their devices."""
        async with self._lock:
            device_ids = self._device_ids()
            if not self._coordinators or not device_ids:
                await self._async_unsubscribe(client)
                return
            client = next(reversed(self._coordinators.values())).client
            if not force and self.active and device_ids == self._subscribed:
                await self._async_confirm(client)
                return
            if self._webhook_id is None:
                self._webhook_id = webhook.async_generate_id()
                webhook.async_register(
                    self.hass,
                    DOMAIN,
                    "Autobayt",
                    self._webhook_id,
                    self._async_handle,
                    local_only=False,
                    allowed_methods=["POST"],
                )
            try:
                url = callback_url(self.hass, self._webhook_id)
            except NoURLAvailableError:
                self._failed("Home Assistant has no public HTTPS address")
                return
            # Refuse callbacks until the new secret is stored, so Autobayt
            # retries any that arrive before the reply.
            self._secret = None
            try:
                reply = await client.set_webhook(url, sorted(device_ids))
            except AutobaytError as err:
                self._failed(f"subscription refused: {err}")
                return
            secret = reply.get("signing_secret")
            generation = reply.get("generation")
            subscription_id = reply.get("id")
            if not (secret and generation and subscription_id):
                self._failed("subscription reply incomplete")
                return
            self._secret = str(secret)
            self._generation = str(generation)
            self._subscription_id = str(subscription_id)
            self._sequence = 0
            self._seen.clear()
            self._subscribed = device_ids
            self.last_error = None
            self._set_active(True)
            _LOGGER.debug("Autobayt push updates active for %s device(s)", len(device_ids))

    async def _async_confirm(self, client: Any) -> None:
        """Check the subscription is still ours.

        Autobayt keeps one subscription per account, so another Home
        Assistant signed in to the same account replaces it. Taking it back
        would make the two fight over it, so this one polls until reloaded.
        """
        try:
            status = await client.get_webhook()
        except AutobaytError as err:
            _LOGGER.debug("Could not read the Autobayt push status: %s", err)
            return
        if status.get("generation") not in (None, self._generation):
            _LOGGER.warning(
                "Another Home Assistant took over Autobayt push updates for this account; "
                "polling instead until the integration is reloaded"
            )
            self._failed("replaced by another subscription", retry=False)

    def _failed(self, reason: str, retry: bool = True) -> None:
        if self.last_error != reason:
            _LOGGER.info("Autobayt push updates unavailable, polling instead: %s", reason)
        self.last_error = reason
        self._next_attempt = (
            time.monotonic() + PUSH_RETRY_INTERVAL.total_seconds() if retry else float("inf")
        )
        self._drop_webhook()
        self._set_active(False)

    async def _async_unsubscribe(self, client: Any) -> None:
        was_active = self.active
        self._drop_webhook()
        self._set_active(False)
        if was_active and client is not None:
            try:
                await client.delete_webhook()
            except AutobaytError as err:
                _LOGGER.debug("Could not stop Autobayt push updates: %s", err)

    def _drop_webhook(self) -> None:
        if self._webhook_id is not None:
            webhook.async_unregister(self.hass, self._webhook_id)
        self._webhook_id = None
        self._secret = None
        self._generation = None
        self._subscription_id = None
        self._subscribed = frozenset()

    def _set_active(self, active: bool) -> None:
        self.active = active
        for coordinator in self._coordinators.values():
            coordinator.set_push_active(active)

    # -- callbacks --------------------------------------------------------

    async def _async_handle(
        self, hass: HomeAssistant, webhook_id: str, request: web.Request
    ) -> web.Response:
        """Verify and apply one pushed snapshot."""
        if self._secret is None or webhook_id != self._webhook_id:
            # Not ready for this subscription yet: Autobayt retries.
            return web.Response(status=503)
        body = await request.read()
        event = self._verify(self._secret, request.headers, body)
        if isinstance(event, int):
            return web.Response(status=event)
        self._apply(event)
        return web.Response(status=200)

    @staticmethod
    def _verify(secret: str, headers: Any, body: bytes) -> dict[str, Any] | int:
        """Return the event of a genuine, recent callback, or an HTTP status."""
        timestamp = headers.get("X-Autobayt-Timestamp", "")
        if not signature_ok(secret, timestamp, body, headers.get("X-Autobayt-Signature", "")):
            return 401
        try:
            sent = int(timestamp)
        except ValueError:
            return 401
        if abs(time.time() - sent) > PUSH_MAX_CLOCK_SKEW:
            return 401
        try:
            event = json.loads(body)
        except ValueError:
            return 400
        if not isinstance(event, dict) or event.get("event_id") != headers.get(
            "X-Autobayt-Event-Id"
        ):
            return 400
        return event

    def _apply(self, event: dict[str, Any]) -> None:
        if (
            event.get("type") != SNAPSHOT_TYPE
            or event.get("schema_version") != SCHEMA_VERSION
            or event.get("subscription_id") != self._subscription_id
            or event.get("generation") != self._generation
        ):
            # Another kind of event, or one for an older subscription:
            # accepted so it is not retried, but not applied.
            return
        sequence = event.get("sequence")
        event_id = str(event.get("event_id"))
        if not isinstance(sequence, int) or sequence <= self._sequence or event_id in self._seen:
            return
        self._sequence = sequence
        self._seen.append(event_id)
        self.events += 1
        self.last_event = dt_util.utcnow()
        devices = [d for d in event.get("devices") or [] if isinstance(d, dict)]
        for coordinator in self._coordinators.values():
            coordinator.async_apply_snapshot(devices)

    def diagnostics(self) -> dict[str, Any]:
        """Return push status without addresses, ids or secrets."""
        return {
            "active": self.active,
            "last_error": self.last_error,
            "devices": len(self._subscribed),
            "events_applied": self.events,
            "last_sequence": self._sequence,
            "last_event": self.last_event.isoformat() if self.last_event else None,
        }
