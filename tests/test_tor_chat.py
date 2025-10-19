import time
from pathlib import Path

import pytest

pytest.importorskip("socks")

from utils.tor_chat import TorChatManager


def wait_for(manager: TorChatManager, event_type: str, timeout: float = 5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for event in manager.poll_events():
            if event.type == event_type:
                return event
        time.sleep(0.05)
    raise AssertionError(f"event {event_type} not received")


def test_tor_chat_message_and_file(tmp_path: Path):
    host_manager = TorChatManager(tmp_path / "host_downloads")
    client_manager = TorChatManager(tmp_path / "client_downloads")

    host_manager.start_host(port=0, handshake="session-test")
    hosting_event = wait_for(host_manager, "hosting")
    port = hosting_event.payload["port"]

    client_manager.connect(host="127.0.0.1", port=port, handshake="session-test")
    wait_for(host_manager, "connected")
    wait_for(client_manager, "connected")

    client_manager.send_message("hello host")
    message = wait_for(host_manager, "message")
    assert message.payload["text"] == "hello host"

    host_manager.send_message("hello client")
    reply = wait_for(client_manager, "message")
    assert reply.payload["text"] == "hello client"

    source_file = tmp_path / "client_payload.txt"
    source_file.write_text("payload", encoding="utf-8")
    client_manager.send_file(source_file)

    saved_path = None
    deadline = time.time() + 5
    offer_id = None
    while time.time() < deadline:
        for event in host_manager.poll_events():
            if event.type == "file_offer":
                offer_id = event.payload["offer_id"]
                host_manager.respond_to_offer(offer_id, True)
            elif event.type == "file_saved" and (offer_id is None or event.payload.get("offer_id") == offer_id):
                saved_path = Path(event.payload["path"])
                break
        if saved_path:
            break
        time.sleep(0.05)
    assert saved_path is not None
    assert saved_path.read_text(encoding="utf-8") == "payload"

    client_manager.stop()
    host_manager.stop()
