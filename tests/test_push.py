"""Push updates: subscription, signed callbacks and the polling fallback."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.autobayt.const import (
    CONF_HOST,
    CONF_LOCATION_ID,
    CONF_LOCATION_NAME,
    CONF_PUSH,
    CONF_TOKEN,
    CONF_USER_ID,
    DEFAULT_HOST,
    DOMAIN,
    PUSH_RECONCILE_INTERVAL,
)
from custom_components.autobayt.diagnostics import async_get_config_entry_diagnostics
from custom_components.autobayt.push import PUSH_MANAGERS, signature_ok
from homeassistant.components.cover import ATTR_CURRENT_POSITION
from homeassistant.const import ATTR_ENTITY_ID
from homeassistant.setup import async_setup_component

from .conftest import LOC_ID, OTHER_LOC_ID, TOKEN, USER_ID, state_of

LOCATION_DEVICES = ["off-1", "pm-1", "sh-1", "sw-1"]


@pytest.fixture
async def public_url(hass):
    """Give Home Assistant a public HTTPS address."""
    assert await async_setup_component(hass, "webhook", {})
    await hass.config.async_update(external_url="https://ha.example.com")


@pytest.fixture
async def client(hass, hass_client_no_auth, public_url):
    """Return an HTTP client for Home Assistant's webhooks."""
    return await hass_client_no_auth()


async def _setup(hass, entry: MockConfigEntry, **options) -> MockConfigEntry:
    entry.add_to_hass(hass)
    if options:
        hass.config_entries.async_update_entry(entry, options=options)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


def _webhook_path(fake) -> str:
    url = fake.webhook_puts[-1]["callback_url"]
    assert url.startswith("https://ha.example.com/api/webhook/")
    return url.removeprefix("https://ha.example.com")


def _event(fake, sequence: int, devices: list[dict[str, Any]], **extra) -> dict[str, Any]:
    return {
        "event_id": f"evt-{sequence}",
        "type": "device_state_snapshot",
        "schema_version": 1,
        "subscription_id": "sub-1",
        "generation": fake.generation,
        "sequence": sequence,
        "observed_at": "2026-11-15T12:00:01.000Z",
        "devices": devices,
        **extra,
    }


async def _post(client, fake, event, *, secret=None, timestamp=None, event_id=None):
    body = json.dumps(event).encode()
    stamp = str(timestamp if timestamp is not None else int(time.time()))
    digest = hmac.new(
        (secret or fake.secret).encode(), stamp.encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    resp = await client.post(
        _webhook_path(fake),
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Autobayt-Event-Id": event_id or event["event_id"],
            "X-Autobayt-Timestamp": stamp,
            "X-Autobayt-Signature": f"sha256={digest}",
        },
    )
    return resp.status


def _hallway(**changes) -> dict[str, Any]:
    device = {
        "device_id": "sw-1",
        "removed": False,
        "available": True,
        "name": "Hallway switch",
        "model_name": "SW200LV1",
        "loc_id": LOC_ID,
        "firmware_version": "1.10.1",
        "shutter_position": None,
        "buttons": [
            {"button_id": 0, "name": "Ceiling light", "switch_state": True},
            {"button_id": 1, "name": "Wall light", "switch_state": True},
        ],
    }
    device.update(changes)
    return device


async def test_subscribes_and_slows_polling(hass, fake, config_entry, client):
    entry = await _setup(hass, config_entry)
    assert len(fake.webhook_puts) == 1
    assert fake.webhook_puts[0]["device_ids"] == LOCATION_DEVICES
    coordinator = entry.runtime_data.devices
    assert coordinator.push_active
    assert coordinator.update_interval == PUSH_RECONCILE_INTERVAL


async def test_snapshot_updates_states(hass, fake, config_entry, client):
    await _setup(hass, config_entry)
    assert state_of(hass, "autobayt_sw-1_1").state == "off"
    shutter = {
        "device_id": "sh-1",
        "available": True,
        "loc_id": LOC_ID,
        "shutter_position": 75,
        "buttons": [
            {"button_id": 0, "switch_state": False},
            {"button_id": 1, "switch_state": False},
            {"button_id": 2, "switch_state": True},
        ],
    }
    offline = {"device_id": "pm-1", "available": False, "loc_id": LOC_ID, "buttons": []}
    assert await _post(client, fake, _event(fake, 2, [_hallway(), shutter, offline])) == 200
    await hass.async_block_till_done()
    assert state_of(hass, "autobayt_sw-1_1").state == "on"
    # The room name is not in snapshots and is kept from get-things.
    data = config_entry.runtime_data.devices.data
    assert data["sw-1"].room_name == "Hallway"
    assert data["sh-1"].buttons[2].name == "Dim"
    assert state_of(hass, "autobayt_sh-1_shutter").attributes[ATTR_CURRENT_POSITION] == 75
    assert state_of(hass, "autobayt_pm-1_0").state == "unavailable"


async def test_removed_device_goes_unavailable(hass, fake, config_entry, client):
    await _setup(hass, config_entry)
    tombstone = {"device_id": "sw-1", "removed": True, "available": False, "buttons": []}
    assert await _post(client, fake, _event(fake, 2, [tombstone])) == 200
    await hass.async_block_till_done()
    assert state_of(hass, "autobayt_sw-1_0").state == "unavailable"


async def test_device_moved_to_another_home_is_dropped(hass, fake, config_entry, client):
    await _setup(hass, config_entry)
    moved = _hallway(loc_id=OTHER_LOC_ID)
    stranger = _hallway(device_id="elsewhere-1", loc_id=OTHER_LOC_ID)
    assert await _post(client, fake, _event(fake, 2, [moved, stranger])) == 200
    await hass.async_block_till_done()
    data = config_entry.runtime_data.devices.data
    assert "sw-1" not in data
    assert "elsewhere-1" not in data


@pytest.mark.parametrize(
    ("kwargs", "status"),
    [
        ({"secret": "wrong"}, 401),
        ({"timestamp": int(time.time()) - 3600}, 401),
        ({"timestamp": "soon"}, 401),
        ({"event_id": "other"}, 400),
    ],
)
async def test_bad_callbacks_are_refused(  # noqa: PLR0917
    hass, fake, config_entry, client, kwargs, status
):
    await _setup(hass, config_entry)
    assert await _post(client, fake, _event(fake, 2, [_hallway()]), **kwargs) == status
    await hass.async_block_till_done()
    assert state_of(hass, "autobayt_sw-1_1").state == "off"


async def test_unsigned_garbage_is_refused(hass, fake, config_entry, client):
    await _setup(hass, config_entry)
    resp = await client.post(_webhook_path(fake), data=b"{}")
    assert resp.status == 401


async def test_stale_duplicate_and_foreign_events_are_ignored(hass, fake, config_entry, client):
    await _setup(hass, config_entry)
    assert await _post(client, fake, _event(fake, 5, [_hallway()])) == 200
    await hass.async_block_till_done()
    assert state_of(hass, "autobayt_sw-1_1").state == "on"
    buttons = [
        {"button_id": 0, "switch_state": True},
        {"button_id": 1, "switch_state": None},
    ]
    off = [_hallway(buttons=buttons)]
    # An older sequence, a replayed event id, another generation, another
    # event type: all acknowledged, none applied.
    ignored = [
        _event(fake, 4, off),
        {**_event(fake, 6, off), "event_id": "evt-5"},
        _event(fake, 7, off, generation="old"),
        _event(fake, 8, off, type="something_new"),
    ]
    for event in ignored:
        assert await _post(client, fake, event) == 200
    await hass.async_block_till_done()
    assert state_of(hass, "autobayt_sw-1_1").state == "on"
    # A newer one is applied; the missing state reads as unknown.
    assert await _post(client, fake, _event(fake, 9, off)) == 200
    await hass.async_block_till_done()
    assert state_of(hass, "autobayt_sw-1_1").state == "unknown"


async def test_callback_before_secret_is_retried(hass, fake, config_entry, client):
    entry = await _setup(hass, config_entry)
    push = entry.runtime_data.devices.push
    push._secret = None
    assert await _post(client, fake, _event(fake, 2, [_hallway()])) == 503


async def test_push_confirms_a_command(hass, fake, config_entry, client):
    await _setup(hass, config_entry)
    fake.apply_triggers = False
    await hass.services.async_call(
        "light",
        "turn_on",
        {ATTR_ENTITY_ID: state_of(hass, "autobayt_sw-1_1").entity_id},
        blocking=True,
    )
    coordinator = config_entry.runtime_data.devices
    assert coordinator.expected_state("sw-1", 1) is True
    assert await _post(client, fake, _event(fake, 2, [_hallway()])) == 200
    assert coordinator.expected_state("sw-1", 1) is None
    assert state_of(hass, "autobayt_sw-1_1").state == "on"


async def test_without_public_url_it_polls(hass, fake, config_entry):
    entry = await _setup(hass, config_entry)
    assert fake.webhook_puts == []
    coordinator = entry.runtime_data.devices
    assert not coordinator.push_active
    assert coordinator.update_interval.total_seconds() == 10
    diag = await async_get_config_entry_diagnostics(hass, entry)
    assert diag["push"]["active"] is False
    assert "public HTTPS" in diag["push"]["last_error"]


async def test_plain_http_address_is_not_used(hass, fake, config_entry):
    assert await async_setup_component(hass, "webhook", {})
    await hass.config.async_update(external_url="http://ha.example.com:8123")
    entry = await _setup(hass, config_entry)
    assert fake.webhook_puts == []
    assert not entry.runtime_data.devices.push_active


async def test_refused_subscription_falls_back_and_retries(
    hass, fake, config_entry, client, freezer
):
    fake.webhook_status = 404
    entry = await _setup(hass, config_entry)
    coordinator = entry.runtime_data.devices
    assert not coordinator.push_active
    assert "404" in coordinator.push.last_error
    # Polls do not retry straight away...
    fake.webhook_status = 200
    await coordinator.async_refresh()
    await hass.async_block_till_done()
    assert fake.webhook_puts == []
    # ...but once the retry interval has passed.
    coordinator.push._next_attempt = 0
    await coordinator.async_refresh()
    await hass.async_block_till_done()
    assert len(fake.webhook_puts) == 1
    assert coordinator.push_active


async def test_new_device_resubscribes(hass, fake, config_entry, client):
    entry = await _setup(hass, config_entry)
    coordinator = entry.runtime_data.devices
    await coordinator.async_refresh()
    await hass.async_block_till_done()
    assert len(fake.webhook_puts) == 1  # nothing changed
    fake.devices.append(
        {
            "device_id": "sw-2",
            "name": "Porch",
            "model_name": "SW100HV1",
            "loc_id": LOC_ID,
            "connection_status": True,
            "buttons": [{"button_id": 0, "name": "Porch light", "switch_state": False}],
        }
    )
    await coordinator.async_refresh()
    await hass.async_block_till_done()
    assert len(fake.webhook_puts) == 2
    assert "sw-2" in fake.webhook_puts[-1]["device_ids"]


async def test_taken_over_by_another_home_assistant(hass, fake, config_entry, client):
    entry = await _setup(hass, config_entry)
    coordinator = entry.runtime_data.devices
    await coordinator.async_refresh()
    await hass.async_block_till_done()
    assert coordinator.push_active  # still ours
    fake.generation = "someone-else"
    await coordinator.async_refresh()
    await hass.async_block_till_done()
    assert not coordinator.push_active
    assert coordinator.update_interval.total_seconds() == 10
    # It does not take the subscription back.
    await coordinator.async_refresh()
    await hass.async_block_till_done()
    assert len(fake.webhook_puts) == 1


async def test_option_off_never_subscribes(hass, fake, config_entry, client):
    entry = await _setup(hass, config_entry, **{CONF_PUSH: False})
    assert fake.webhook_puts == []
    assert entry.runtime_data.devices.push is None


async def test_unload_stops_the_subscription(hass, fake, config_entry, client):
    entry = await _setup(hass, config_entry)
    path = _webhook_path(fake)
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert fake.webhook_deletes == 1
    assert USER_ID not in hass.data.get(PUSH_MANAGERS, {})
    # The webhook is gone: callbacks are acknowledged and dropped.
    resp = await client.post(path, data=b"{}")
    assert resp.status == 200


async def test_two_homes_share_one_subscription(hass, fake, config_entry, client):
    fake.locations.append({"_id": OTHER_LOC_ID, "name": "Farm", "user_id": USER_ID})
    first = await _setup(hass, config_entry)
    second = await _setup(
        hass,
        MockConfigEntry(
            domain=DOMAIN,
            title="Farm",
            unique_id=f"{USER_ID}_{OTHER_LOC_ID}",
            data={
                CONF_HOST: DEFAULT_HOST,
                CONF_TOKEN: TOKEN,
                CONF_USER_ID: USER_ID,
                CONF_LOCATION_ID: OTHER_LOC_ID,
                CONF_LOCATION_NAME: "Farm",
            },
        ),
    )
    assert fake.webhook_puts[-1]["device_ids"] == sorted([*LOCATION_DEVICES, "elsewhere-1"])
    assert first.runtime_data.devices.push is second.runtime_data.devices.push
    # One snapshot reaches both homes.
    lamp = _hallway(device_id="elsewhere-1", loc_id=OTHER_LOC_ID)
    lamp["buttons"] = [{"button_id": 0, "name": "Lamp", "switch_state": False}]
    assert await _post(client, fake, _event(fake, 2, [_hallway(), lamp])) == 200
    await hass.async_block_till_done()
    assert state_of(hass, "autobayt_sw-1_1").state == "on"
    assert state_of(hass, "autobayt_elsewhere-1_0").state == "off"
    # Unloading one home keeps the other subscribed.
    assert await hass.config_entries.async_unload(second.entry_id)
    assert fake.webhook_puts[-1]["device_ids"] == LOCATION_DEVICES
    assert fake.webhook_deletes == 0
    assert await hass.config_entries.async_unload(first.entry_id)
    assert fake.webhook_deletes == 1


async def test_diagnostics_show_push_without_secrets(hass, fake, config_entry, client):
    entry = await _setup(hass, config_entry)
    diag = await async_get_config_entry_diagnostics(hass, entry)
    push = diag["push"]
    assert push["active"] is True
    assert push["devices"] == 4
    assert push["delivery"]["sequence"] == 3
    text = json.dumps(diag)
    assert fake.secret not in text
    assert "/api/webhook/" not in text
    assert "sub-1" not in text


def test_signature_check():
    body = b'{"a":1}'
    good = hmac.new(b"k", b"1." + body, hashlib.sha256).hexdigest()
    assert signature_ok("k", "1", body, f"sha256={good}")
    assert not signature_ok("k", "1", body, good)
    assert not signature_ok("k", "2", body, f"sha256={good}")
