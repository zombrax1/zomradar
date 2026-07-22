import io
import os
import re
import shlex
import shutil
import subprocess
import tarfile
from email.utils import parsedate_to_datetime
from pathlib import Path
from threading import Lock
from time import monotonic


AVATAR_PATH = re.compile(
    r"^\d{4}/\d{2}/\d{2}/[A-Za-z0-9_-]+_(\d{9,12})\.png$"
)
PNG_HEADER = b"\x89PNG\r\n\x1a\n"
MUMU_CONTENT = (
    "/sdcard/Android/data/com.gof.global/files/"
    "com.Tivadar.Best.HTTP.v3/LocalCache/Content"
)
MAX_AVATAR_BYTES = 5 * 1024 * 1024


def avatar_epoch(avatar_path):
    match = AVATAR_PATH.fullmatch(avatar_path or "")
    return int(match.group(1)) if match else None


def cached_avatar_epoch(headers):
    match = re.search(rb"Last-Modified:([^\r\n]+)", headers)
    if not match:
        return None
    try:
        modified = parsedate_to_datetime(match.group(1).decode("ascii"))
    except (UnicodeDecodeError, TypeError, ValueError):
        return None
    return int(modified.timestamp()) - 1


def valid_png(data):
    return bool(data) and len(data) <= MAX_AVATAR_BYTES and data.startswith(PNG_HEADER)


class AvatarCache:
    """Resolve protocol avatar paths from a local or MuMu BestHTTP cache."""

    def __init__(self, local_root=None, adb=None, serial=None):
        configured_root = local_root or os.getenv("ZOMRADAR_AVATAR_CACHE_DIR")
        self.local_root = Path(configured_root) if configured_root else None
        if self.local_root and (self.local_root / "Content").is_dir():
            self.local_root = self.local_root / "Content"
        self.adb = adb or os.getenv("ZOMRADAR_ADB")
        self.serial = serial or os.getenv("ZOMRADAR_ADB_SERIAL")
        self._local_index = None
        self._adb_index = None
        self._adb_indexed_at = 0
        self._resolved = {}
        self._missing = {}
        self._adb_target = None
        self._lock = Lock()

    def resolve(self, avatar_path):
        epoch = avatar_epoch(avatar_path)
        if epoch is None:
            return None
        with self._lock:
            if avatar_path in self._resolved:
                return self._resolved[avatar_path]
            if self._missing.get(avatar_path, 0) > monotonic():
                return None
            data = self._resolve_local(epoch) or self._resolve_adb(epoch)
            if valid_png(data):
                self._resolved[avatar_path] = data
                return data
            self._missing[avatar_path] = monotonic() + 30
        return None

    def _build_local_index(self):
        index = {}
        if self.local_root and self.local_root.is_dir():
            for headers_path in self.local_root.rglob("headers.cache"):
                try:
                    epoch = cached_avatar_epoch(headers_path.read_bytes())
                except OSError:
                    continue
                if epoch is not None:
                    index.setdefault(epoch, []).append(headers_path.with_name("content.cache"))
        self._local_index = index

    def _resolve_local(self, epoch):
        if self._local_index is None:
            self._build_local_index()
        matches = self._local_index.get(epoch, [])
        if len(matches) != 1:
            return None
        try:
            return matches[0].read_bytes()
        except OSError:
            return None

    def _find_adb(self):
        if self.adb and Path(self.adb).is_file():
            return self.adb
        if found := shutil.which("adb"):
            return found
        for drive in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            for folder in ("Program Files", "Program Files (x86)"):
                root = Path(f"{drive}:/{folder}/Netease/MuMuPlayer/nx_device")
                if not root.is_dir():
                    continue
                matches = sorted(root.glob("*/shell/adb.exe"), reverse=True)
                if matches:
                    return str(matches[0])
        return None

    @staticmethod
    def _run(command, **kwargs):
        if os.name == "nt":
            kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)
        return subprocess.run(command, timeout=12, **kwargs)

    def _find_adb_target(self):
        if self._adb_target:
            return self._adb_target
        adb = self._find_adb()
        if not adb:
            return None
        serials = [self.serial] if self.serial else []
        if not serials:
            try:
                result = self._run([adb, "devices"], capture_output=True, text=True)
                serials = [
                    line.split()[0]
                    for line in result.stdout.splitlines()
                    if line.strip().endswith("\tdevice")
                ]
            except (OSError, subprocess.SubprocessError):
                return None
        for serial in serials:
            try:
                result = self._run(
                    [adb, "-s", serial, "shell", "test", "-d", MUMU_CONTENT],
                    capture_output=True,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            if result.returncode == 0:
                self._adb_target = (adb, serial)
                return self._adb_target
        return None

    def _build_adb_index(self):
        target = self._find_adb_target()
        if not target:
            self._adb_index = {}
            self._adb_indexed_at = monotonic()
            return
        adb, serial = target
        root = shlex.quote(MUMU_CONTENT)
        index = {}
        try:
            result = self._run(
                [adb, "-s", serial, "exec-out", "sh", "-c", f"cd {root} && tar -cf - */headers.cache"],
                capture_output=True,
            )
            if result.returncode == 0:
                with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
                    for member in archive.getmembers():
                        source = archive.extractfile(member)
                        if not source or not member.name.endswith("/headers.cache"):
                            continue
                        epoch = cached_avatar_epoch(source.read())
                        if epoch is None:
                            continue
                        folder = member.name.split("/", 1)[0]
                        index.setdefault(epoch, []).append(f"{MUMU_CONTENT}/{folder}/content.cache")
        except (OSError, subprocess.SubprocessError, tarfile.TarError):
            self._adb_target = None
        self._adb_index = index
        self._adb_indexed_at = monotonic()

    def _resolve_adb(self, epoch):
        if self._adb_index is None or (
            epoch not in self._adb_index and monotonic() - self._adb_indexed_at >= 30
        ):
            self._build_adb_index()
        matches = self._adb_index.get(epoch, [])
        if len(matches) != 1 or not self._adb_target:
            return None
        adb, serial = self._adb_target
        try:
            image = self._run(
                [adb, "-s", serial, "exec-out", "cat", matches[0]],
                capture_output=True,
            )
            return image.stdout if image.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            self._adb_target = None
            return None
