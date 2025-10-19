"""Peer-to-peer Tor mediated chat helpers."""
from __future__ import annotations

import base64
import json
import queue
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import socks

try:  # pragma: no cover - optional dependency for runtime
    from stem.control import Controller
except Exception:  # pragma: no cover - stem optional for tests
    Controller = None  # type: ignore


@dataclass
class ChatEvent:
    """Event emitted by :class:`TorChatManager`."""

    type: str
    message: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HostInfo:
    address: str
    port: int
    onion: Optional[str] = None


class ChatWorker(threading.Thread):
    """Background worker maintaining a single chat session."""

    def __init__(
        self,
        *,
        mode: str,
        handshake: str,
        downloads_dir: Path,
        event_queue: "queue.Queue[ChatEvent]",
        command_queue: "queue.Queue[Dict[str, Any]]",
        host: str = "127.0.0.1",
        port: int = 0,
        socks_host: Optional[str] = None,
        socks_port: Optional[int] = None,
        control_port: Optional[int] = None,
        control_password: Optional[str] = None,
    ) -> None:
        super().__init__(daemon=True)
        self.mode = mode
        self.handshake = handshake
        self.downloads_dir = downloads_dir
        self.event_queue = event_queue
        self.command_queue = command_queue
        self.host = host
        self.port = port
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.control_port = control_port
        self.control_password = control_password
        self._stop_event = threading.Event()
        self._connection: Optional[socket.socket] = None
        self._connection_lock = threading.Lock()
        self._reader_thread: Optional[threading.Thread] = None
        self._pending_files: Dict[str, Dict[str, Any]] = {}
        self._file_writers: Dict[str, Any] = {}
        self._listening_socket: Optional[socket.socket] = None
        self.onion_address: Optional[str] = None

    def stop(self) -> None:
        self._stop_event.set()
        with self._connection_lock:
            if self._connection:
                try:
                    self._connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    self._connection.close()
                except OSError:
                    pass
                self._connection = None
        if self._listening_socket:
            try:
                self._listening_socket.close()
            except OSError:
                pass
        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=1.0)

    def run(self) -> None:  # pragma: no cover - thin wrapper
        try:
            if self.mode == "host":
                self._run_host()
            else:
                self._run_client()
        except Exception as exc:  # pragma: no cover - defensive path
            self.event_queue.put(ChatEvent("error", message=str(exc)))
        finally:
            self.stop()

    # --- host lifecycle -------------------------------------------------
    def _run_host(self) -> None:
        self._listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listening_socket.bind((self.host, self.port))
        self._listening_socket.listen(1)
        _, actual_port = self._listening_socket.getsockname()
        self.port = actual_port
        if self.control_port is not None and Controller is not None:
            try:
                self.onion_address = self._create_hidden_service(actual_port)
            except Exception as exc:  # pragma: no cover
                self.event_queue.put(ChatEvent("error", message=f"Tor hidden service error: {exc}"))
        address = f"{self.host}:{actual_port}"
        self.event_queue.put(
            ChatEvent("hosting", payload={"address": address, "port": actual_port, "onion": self.onion_address})
        )
        self._listening_socket.settimeout(1.0)
        while not self._stop_event.is_set():
            try:
                client, _ = self._listening_socket.accept()
            except socket.timeout:
                continue
            with self._connection_lock:
                if self._connection is not None:
                    client.close()
                    continue
                self._connection = client
            self._enter_session(client)
            with self._connection_lock:
                self._connection = None
            if self._stop_event.is_set():
                break

    def _create_hidden_service(self, local_port: int) -> Optional[str]:
        if Controller is None:
            return None
        with Controller.from_port(port=self.control_port) as controller:
            controller.authenticate(password=self.control_password)
            result = controller.create_ephemeral_hidden_service({80: local_port}, await_publication=True)
            return f"{result.service_id}.onion"

    # --- client lifecycle -----------------------------------------------
    def _run_client(self) -> None:
        sock = self._open_socket(self.host, self.port)
        with self._connection_lock:
            self._connection = sock
        self._enter_session(sock)

    def _open_socket(self, host: str, port: int) -> socket.socket:
        if self.socks_host and self.socks_port:
            sock: socket.socket = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, self.socks_host, self.socks_port)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((host, port))
        sock.settimeout(None)
        return sock

    # --- session loop ---------------------------------------------------
    def _enter_session(self, sock: socket.socket) -> None:
        sock_file = sock.makefile("rwb")
        self._send_json(sock_file, {"type": "hello", "session": self.handshake})
        hello = self._read_json(sock_file)
        if hello.get("type") != "hello" or hello.get("session") != self.handshake:
            self.event_queue.put(ChatEvent("error", message="Handshake failed"))
            sock.close()
            return
        self.event_queue.put(ChatEvent("connected", payload={"peer": sock.getpeername()}))
        self._reader_thread = threading.Thread(
            target=self._reader_loop, args=(sock, sock_file), daemon=True
        )
        self._reader_thread.start()
        try:
            while not self._stop_event.is_set():
                try:
                    command = self.command_queue.get(timeout=0.2)
                except queue.Empty:
                    continue
                op = command.get("op")
                if op == "send_message":
                    self._send_json(sock_file, {"type": "message", "text": command["text"]})
                elif op == "send_file":
                    self._send_file(sock_file, command["path"], command.get("name"))
                elif op == "respond_file":
                    self._send_json(
                        sock_file,
                        {
                            "type": "file_accept",
                            "offer_id": command["offer_id"],
                            "accept": command["accept"],
                        },
                    )
                elif op == "stop":
                    break
        finally:
            self._send_json(sock_file, {"type": "goodbye"})
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
            self.event_queue.put(ChatEvent("disconnected"))

    def _reader_loop(self, sock: socket.socket, sock_file: Any) -> None:
        while not self._stop_event.is_set():
            try:
                payload = self._read_json(sock_file)
            except Exception:
                break
            if not payload:
                break
            self._handle_payload(payload)

    # --- protocol helpers -----------------------------------------------
    def _send_json(self, sock_file: Any, payload: Dict[str, Any]) -> None:
        blob = json.dumps(payload).encode("utf-8") + b"\n"
        sock_file.write(blob)
        sock_file.flush()

    def _read_json(self, sock_file: Any) -> Dict[str, Any]:
        line = sock_file.readline()
        if not line:
            return {}
        return json.loads(line.decode("utf-8"))

    def _handle_payload(self, payload: Dict[str, Any]) -> None:
        ptype = payload.get("type")
        if ptype == "message":
            text = payload.get("text", "")
            self.event_queue.put(ChatEvent("message", payload={"text": text}))
        elif ptype == "file_offer":
            offer_id = payload["offer_id"]
            metadata = {
                "offer_id": offer_id,
                "name": payload.get("name", "transfer.bin"),
                "size": payload.get("size", 0),
            }
            self._pending_files[offer_id] = metadata
            self.event_queue.put(ChatEvent("file_offer", payload=metadata))
        elif ptype == "file_accept":
            offer_id = payload.get("offer_id")
            accepted = payload.get("accept", False)
            meta = self._pending_files.get(offer_id)
            if meta:
                meta["accepted"] = accepted
                meta["notified"] = True
        elif ptype == "file_chunk":
            offer_id = payload["offer_id"]
            chunk = base64.b64decode(payload.get("data", ""))
            final = payload.get("final", False)
            meta = self._pending_files.setdefault(offer_id, {"name": "transfer.bin"})
            if not meta.get("accepted"):
                return
            writer = self._file_writers.get(offer_id)
            if writer is None:
                path = self.downloads_dir / meta.get("name", "transfer.bin")
                writer = path.open("wb")
                meta["path"] = str(path)
                self._file_writers[offer_id] = writer
            writer.write(chunk)
            if final:
                writer.flush()
                writer.close()
                self._file_writers.pop(offer_id, None)
                self.event_queue.put(
                    ChatEvent("file_saved", payload={"offer_id": offer_id, "path": meta.get("path")})
                )
        elif ptype == "goodbye":
            self._stop_event.set()

    def _send_file(self, sock_file: Any, path: Path, name_override: Optional[str]) -> None:
        if not path.exists():
            self.event_queue.put(ChatEvent("error", message="File missing"))
            return
        offer_id = uuid.uuid4().hex
        size = path.stat().st_size
        name = name_override or path.name
        meta = {"offer_id": offer_id, "name": name, "size": size, "accepted": False}
        self._pending_files[offer_id] = meta
        self._send_json(
            sock_file,
            {"type": "file_offer", "offer_id": offer_id, "name": name, "size": size},
        )
        deadline = time.time() + 30
        while time.time() < deadline and not meta.get("notified"):
            time.sleep(0.1)
        if not meta.get("accepted"):
            self.event_queue.put(ChatEvent("status", message="Remote peer declined file"))
            return
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(32768)
                if not chunk:
                    final = True
                else:
                    final = False
                self._send_json(
                    sock_file,
                    {
                        "type": "file_chunk",
                        "offer_id": offer_id,
                        "data": base64.b64encode(chunk).decode("ascii"),
                        "final": final,
                    },
                )
                if final:
                    break
        self.event_queue.put(ChatEvent("status", message=f"Sent {name}"))


class TorChatManager:
    """Threaded chat helper polled by the UI."""

    def __init__(self, downloads_dir: Path) -> None:
        self.downloads_dir = downloads_dir
        self.downloads_dir.mkdir(parents=True, exist_ok=True)
        self._event_queue: "queue.Queue[ChatEvent]" = queue.Queue()
        self._command_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._worker: Optional[ChatWorker] = None

    def start_host(
        self,
        *,
        port: int,
        handshake: str,
        control_port: Optional[int] = None,
        control_password: Optional[str] = None,
    ) -> HostInfo:
        self.stop()
        self._worker = ChatWorker(
            mode="host",
            handshake=handshake,
            downloads_dir=self.downloads_dir,
            event_queue=self._event_queue,
            command_queue=self._command_queue,
            port=port,
            control_port=control_port,
            control_password=control_password,
        )
        self._worker.start()
        return HostInfo(address="127.0.0.1", port=port)

    def connect(
        self,
        *,
        host: str,
        port: int,
        handshake: str,
        socks_host: Optional[str] = None,
        socks_port: Optional[int] = None,
    ) -> None:
        self.stop()
        self._worker = ChatWorker(
            mode="client",
            handshake=handshake,
            downloads_dir=self.downloads_dir,
            event_queue=self._event_queue,
            command_queue=self._command_queue,
            host=host,
            port=port,
            socks_host=socks_host,
            socks_port=socks_port,
        )
        self._worker.start()

    def send_message(self, text: str) -> None:
        if not text.strip():
            return
        self._command_queue.put({"op": "send_message", "text": text.strip()})

    def send_file(self, path: Path) -> None:
        self._command_queue.put({"op": "send_file", "path": path})

    def respond_to_offer(self, offer_id: str, accept: bool) -> None:
        self._command_queue.put({"op": "respond_file", "offer_id": offer_id, "accept": accept})

    def stop(self) -> None:
        if self._worker:
            self._command_queue.put({"op": "stop"})
            self._worker.stop()
            self._worker = None
        while not self._event_queue.empty():
            try:
                self._event_queue.get_nowait()
            except queue.Empty:
                break

    def poll_events(self) -> List[ChatEvent]:
        events: List[ChatEvent] = []
        while True:
            try:
                events.append(self._event_queue.get_nowait())
            except queue.Empty:
                break
        return events
