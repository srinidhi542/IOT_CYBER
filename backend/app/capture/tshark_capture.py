import os
import sys
import time
import shutil
import logging
import subprocess
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional
import psutil

logger = logging.getLogger(__name__)

# Standard locations where TShark is typically installed on Windows
STANDARD_TSHARK_PATHS = [
    os.environ.get("TSHARK_PATH", ""),
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    r"C:\Wireshark\tshark.exe",
]


def find_tshark_path() -> Optional[str]:
    """
    Locates the TShark executable from environment variables,
    system PATH, or standard Windows installation paths.
    """
    which_path = shutil.which("tshark")
    if which_path and os.path.exists(which_path):
        return which_path

    for candidate in STANDARD_TSHARK_PATHS:
        if candidate and os.path.exists(candidate):
            return candidate

    return None


def get_network_interfaces() -> List[Dict[str, Any]]:
    """
    Discovers available network interfaces on the host machine.
    Combines TShark interface enumeration (if available) with
    system psutil network interface discovery.
    """
    interfaces = []
    tshark_path = find_tshark_path()

    # 1. Try discovering via TShark -D
    tshark_ifaces: Dict[str, str] = {}
    if tshark_path:
        try:
            result = subprocess.run(
                [tshark_path, "-D"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    # Format: "1. \Device\NPF_{GUID} (Ethernet)" or "1. Wi-Fi"
                    parts = line.split(". ", 1)
                    if len(parts) == 2:
                        idx, desc = parts[0].strip(), parts[1].strip()
                        tshark_ifaces[idx] = desc
        except Exception as e:
            logger.warning(f"Error executing tshark -D: {e}")

    # 2. Get system adapter details via psutil
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    seen_names = set()

    for iface_name, addr_list in addrs.items():
        seen_names.add(iface_name)
        ip_v4 = None
        mac_addr = None
        for addr in addr_list:
            if addr.family == psutil.AF_LINK or addr.family == -1:
                mac_addr = addr.address
            elif addr.family == 2:  # AF_INET (IPv4)
                ip_v4 = addr.address

        is_up = stats[iface_name].isup if iface_name in stats else True
        speed = stats[iface_name].speed if iface_name in stats else 0
        is_loopback = "loopback" in iface_name.lower() or ip_v4 == "127.0.0.1"

        # Match with TShark index if available
        matched_idx = None
        for t_idx, t_desc in tshark_ifaces.items():
            if iface_name.lower() in t_desc.lower():
                matched_idx = t_idx
                break

        interfaces.append({
            "id": matched_idx or iface_name,
            "name": iface_name,
            "description": f"{iface_name} ({ip_v4 or 'No IPv4'})" + (f" - {mac_addr}" if mac_addr else ""),
            "ip_address": ip_v4,
            "mac_address": mac_addr,
            "is_up": is_up,
            "is_loopback": is_loopback,
            "tshark_supported": bool(tshark_path)
        })

    # If tshark had interfaces not mapped to psutil names, add them
    for t_idx, t_desc in tshark_ifaces.items():
        if not any(iface["id"] == t_idx for iface in interfaces):
            interfaces.append({
                "id": t_idx,
                "name": t_desc,
                "description": f"TShark Adapter [{t_idx}]: {t_desc}",
                "ip_address": None,
                "mac_address": None,
                "is_up": True,
                "is_loopback": "loopback" in t_desc.lower(),
                "tshark_supported": True
            })

    # Ensure loopback or standard fallback always present
    if not interfaces:
        interfaces.append({
            "id": "1",
            "name": "Default Adapter",
            "description": "System Default Network Interface",
            "ip_address": "127.0.0.1",
            "mac_address": None,
            "is_up": True,
            "is_loopback": True,
            "tshark_supported": bool(tshark_path)
        })

    return interfaces


def _count_packets_in_pcap(pcap_path: str) -> int:
    """
    Counts the number of packets in a PCAP file without loading all into memory.
    Uses TShark -r if available (fast), falls back to Scapy rdpcap.
    Returns 0 on failure — never raises.
    """
    if not os.path.exists(pcap_path):
        return 0

    # Try TShark fast count first
    tshark_path = find_tshark_path()
    if tshark_path:
        try:
            result = subprocess.run(
                [tshark_path, "-r", pcap_path, "-T", "fields", "-e", "frame.number"],
                capture_output=True, text=True, timeout=10, check=False
            )
            if result.returncode == 0 and result.stdout.strip():
                lines = [l for l in result.stdout.strip().splitlines() if l.strip()]
                return len(lines)
        except Exception:
            pass

    # Fallback: Scapy
    try:
        from scapy.utils import rdpcap
        pkts = rdpcap(pcap_path)
        return len(pkts)
    except Exception as ex:
        logger.warning(f"Could not count packets in {pcap_path}: {ex}")
        return 0


class CaptureSession:
    def __init__(
        self,
        session_id: str,
        interface: str,
        output_pcap: str,
        mode: str = "tshark"
    ):
        self.session_id = session_id
        self.interface = interface
        self.output_pcap = output_pcap
        self.mode = mode
        self.is_capturing = False
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.packet_count = 0
        self.file_size = 0
        self.error: Optional[str] = None
        self.process: Optional[subprocess.Popen] = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._tshark_stderr_lines: List[str] = []  # captures TShark progress lines

    def _read_tshark_stderr(self):
        """
        Background thread: reads TShark stderr to extract live packet count.
        TShark writes progress lines like "Capturing on 'Wi-Fi'\n100 packets captured"
        to stderr. We parse these to update packet_count in real time.
        """
        if not self.process or not self.process.stderr:
            return
        try:
            for line in self.process.stderr:
                line = line.strip()
                if not line:
                    continue
                self._tshark_stderr_lines.append(line)
                # TShark prints "N packets captured" or "N " periodically
                if "packet" in line.lower():
                    parts = line.split()
                    for i, part in enumerate(parts):
                        try:
                            count = int(part)
                            if count > 0:
                                self.packet_count = count
                                break
                        except ValueError:
                            continue
        except Exception:
            pass

    def to_dict(self) -> Dict[str, Any]:
        duration = 0.0
        if self.start_time:
            end = self.end_time or datetime.now()
            duration = round((end - self.start_time).total_seconds(), 2)

        file_size = 0
        if os.path.exists(self.output_pcap):
            try:
                file_size = os.path.getsize(self.output_pcap)
            except Exception:
                file_size = self.file_size

        return {
            "session_id": self.session_id,
            "interface": self.interface,
            "output_pcap": self.output_pcap,
            "mode": self.mode,
            "is_capturing": self.is_capturing,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": duration,
            "packet_count": self.packet_count,
            "file_size": file_size,
            "error": self.error,
            "tshark_available": bool(find_tshark_path())
        }


class CaptureManager:
    """
    Singleton Manager for Network Packet Captures.
    Supports TShark subprocess execution only — no simulated/synthetic fallback.
    If TShark is unavailable, an error is raised so the user knows to install it.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CaptureManager, cls).__new__(cls)
            cls._instance._active_session = None
            cls._instance._lock = threading.Lock()
        return cls._instance

    @property
    def active_session(self) -> Optional[CaptureSession]:
        return self._active_session

    def start_capture(
        self,
        interface: str,
        output_dir: str,
        duration_limit: Optional[int] = None,
        packet_limit: Optional[int] = None
    ) -> CaptureSession:
        with self._lock:
            if self._active_session and self._active_session.is_capturing:
                raise RuntimeError("A packet capture session is already in progress.")

            tshark_path = find_tshark_path()
            if not tshark_path:
                raise RuntimeError(
                    "TShark is not installed or not on PATH. "
                    "Install Wireshark (with TShark) from https://www.wireshark.org/download.html "
                    "to enable live packet capture."
                )

            session_id = f"cap_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            os.makedirs(output_dir, exist_ok=True)
            output_pcap = os.path.join(output_dir, f"{session_id}.pcap")

            session = CaptureSession(
                session_id=session_id,
                interface=interface,
                output_pcap=output_pcap,
                mode="tshark"
            )
            session.start_time = datetime.now()
            session.is_capturing = True

            # Resolve interface name → TShark index or NPF GUID
            iface_arg = str(interface)
            try:
                all_ifaces = get_network_interfaces()
                matched = next(
                    (i for i in all_ifaces if i["name"] == interface or i["id"] == interface),
                    None
                )
                if matched and matched.get("id"):
                    iface_arg = str(matched["id"])
            except Exception as ie:
                logger.warning(f"Interface resolution failed, using raw name: {ie}")

            cmd = [tshark_path, "-i", iface_arg, "-F", "pcap", "-w", output_pcap]
            if duration_limit and duration_limit > 0:
                cmd.extend(["-a", f"duration:{duration_limit}"])
            if packet_limit and packet_limit > 0:
                cmd.extend(["-c", str(packet_limit)])

            logger.info(f"Starting TShark capture: {' '.join(cmd)}")
            try:
                session.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                # Start background thread to read live packet count from TShark stderr
                stderr_thread = threading.Thread(
                    target=session._read_tshark_stderr,
                    daemon=True
                )
                stderr_thread.start()
                logger.info(
                    f"TShark started (PID={session.process.pid}) on interface '{iface_arg}' "
                    f"→ {output_pcap}"
                )
            except Exception as e:
                session.is_capturing = False
                session.error = str(e)
                logger.error(f"Failed to spawn TShark process: {e}")
                raise RuntimeError(f"Failed to start TShark: {e}")

            self._active_session = session
            return session

    def stop_capture(self) -> Dict[str, Any]:
        with self._lock:
            if not self._active_session:
                raise RuntimeError("No active packet capture session to stop.")

            session = self._active_session
            session.is_capturing = False
            session.end_time = datetime.now()

            # Terminate TShark subprocess
            if session.process:
                try:
                    session.process.terminate()
                    session.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        session.process.kill()
                        session.process.wait(timeout=2)
                    except Exception:
                        pass
                except Exception:
                    pass
                session.process = None

            # Count actual packets captured from the real PCAP file
            if os.path.exists(session.output_pcap):
                session.file_size = os.path.getsize(session.output_pcap)
                real_count = _count_packets_in_pcap(session.output_pcap)
                session.packet_count = real_count
                logger.info(
                    f"Capture stopped. PCAP: {session.output_pcap} | "
                    f"File size: {session.file_size} bytes | "
                    f"Packets captured: {real_count}"
                )
                if real_count == 0:
                    logger.warning(
                        "TShark captured 0 packets. Possible causes: "
                        "(1) Wrong interface selected — check /capture/interfaces. "
                        "(2) No network activity during capture window. "
                        "(3) Npcap/WinPcap not installed or requires admin privileges. "
                        "Run the backend as Administrator for raw packet access."
                    )
            else:
                logger.warning(f"PCAP file not found after capture: {session.output_pcap}")

            return session.to_dict()

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            if not self._active_session:
                return {
                    "is_capturing": False,
                    "session_id": None,
                    "interface": None,
                    "output_pcap": None,
                    "duration": 0.0,
                    "packet_count": 0,
                    "file_size": 0,
                    "tshark_available": bool(find_tshark_path()),
                    "tshark_path": find_tshark_path()
                }

            session = self._active_session

            # Check if TShark process has terminated on its own (e.g. duration limit)
            if session.process and session.process.poll() is not None:
                if session.is_capturing:
                    session.is_capturing = False
                    session.end_time = datetime.now()
                    # Update packet count from file
                    if os.path.exists(session.output_pcap):
                        session.file_size = os.path.getsize(session.output_pcap)
                        real_count = _count_packets_in_pcap(session.output_pcap)
                        session.packet_count = real_count
                        logger.info(
                            f"TShark process ended (duration limit or packet limit reached). "
                            f"Captured {real_count} packets."
                        )

            return session.to_dict()


# Global capture manager singleton
capture_manager = CaptureManager()
