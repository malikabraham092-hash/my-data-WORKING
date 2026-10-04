from flask import Flask, send_from_directory, jsonify
from scapy.all import ARP, Ether, srp
import socket
import subprocess
import concurrent.futures
import os

app = Flask(__name__)

# ============================================================
# PORTS / SERVICES
# ============================================================

PORTS = {
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    8000: "Camera Web/API",
    8008: "Chromecast",
    8009: "Chromecast",
    8080: "HTTP Alternate",
    8081: "Camera Web/API",
    8899: "ONVIF",
    9000: "Camera/API",
    9100: "Printer",
    32400: "Plex",
    62078: "Apple Device",
}

# ============================================================
# CAMERA HOSTNAME WORDS
# ============================================================

CAMERA_WORDS = [
    "camera", "cam", "cctv", "ipcam", "ipc",
    "nvr", "dvr", "doorbell", "security",
    "surveillance", "reolink", "hikvision",
    "dahua", "arlo", "ring", "wyze",
    "eufy", "amcrest", "axis", "foscam",
    "unifi", "unifi-video"
]

# ============================================================
# OTHER DEVICE WORDS
# ============================================================

DEVICE_WORDS = {
    "iphone": ("📱", "iPhone"),
    "ipad": ("📱", "iPad"),
    "android": ("📱", "Android Phone"),
    "galaxy": ("📱", "Samsung Phone / Tablet"),

    "macbook": ("💻", "MacBook"),
    "imac": ("🖥️", "iMac"),
    "macmini": ("🖥️", "Mac mini"),

    "printer": ("🖨️", "Printer"),
    "epson": ("🖨️", "Epson Printer"),
    "canon": ("🖨️", "Canon Printer"),
    "brother": ("🖨️", "Brother Printer"),

    "samsung": ("📺", "Samsung Device"),
    "bravia": ("📺", "Sony Bravia TV"),
    "roku": ("📺", "Roku"),
    "firetv": ("📺", "Amazon Fire TV"),
    "appletv": ("📺", "Apple TV"),
    "chromecast": ("📺", "Chromecast"),

    "xbox": ("🎮", "Xbox"),
    "playstation": ("🎮", "PlayStation"),
    "ps5": ("🎮", "PlayStation 5"),
    "ps4": ("🎮", "PlayStation 4"),
    "nintendo": ("🎮", "Nintendo Device"),
    "switch": ("🎮", "Nintendo Switch"),

    "sonos": ("🔊", "Sonos Speaker"),
    "speaker": ("🔊", "Smart Speaker"),
    "echo": ("🔊", "Amazon Echo"),

    "router": ("🛜", "Router"),
    "gateway": ("🛜", "Network Gateway"),
}

# ============================================================
# HOSTNAME
# ============================================================

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


# ============================================================
# PORT SCANNING
# ============================================================

def check_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.35)

        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            return port

    except Exception:
        pass

    return None


def scan_ports(ip):
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=20
    ) as executor:

        futures = [
            executor.submit(check_port, ip, port)
            for port in PORTS
        ]

        for future in futures:
            result = future.result()

            if result is not None:
                open_ports.append(result)

    open_ports.sort()
    return open_ports


# ============================================================
# DEVICE IDENTIFICATION
# ============================================================

def identify_device(hostname, open_ports):

    text = hostname.lower()

    camera_score = 0
    camera_reasons = []

    # Camera hostname
    for word in CAMERA_WORDS:
        if word in text:
            camera_score += 45

            camera_reasons.append(
                f"Camera-related hostname: '{word}'"
            )

            break

    # RTSP
    if 554 in open_ports:
        camera_score += 45
        camera_reasons.append(
            "RTSP service detected"
        )

    # ONVIF
    if 8899 in open_ports:
        camera_score += 45
        camera_reasons.append(
            "Possible ONVIF service detected"
        )

    # Camera web/API ports
    camera_web_ports = {8000, 8081, 9000}

    found_camera_ports = (
        camera_web_ports.intersection(set(open_ports))
    )

    if found_camera_ports:
        camera_score += 20

        camera_reasons.append(
            "Camera/API web port detected"
        )

    # Camera result
    if camera_score >= 70:
        return {
            "icon": "📷",
            "type": "Likely Security Camera",
            "confidence": "HIGH",
            "score": min(camera_score, 100),
            "reasons": camera_reasons
        }

    if camera_score >= 40:
        return {
            "icon": "📷",
            "type": "Possible Security Camera",
            "confidence": "MEDIUM",
            "score": camera_score,
            "reasons": camera_reasons
        }

    # Other devices
    for word, result in DEVICE_WORDS.items():

        if word in text:
            return {
                "icon": result[0],
                "type": result[1],
                "confidence": "HIGH",
                "score": 90,
                "reasons": [
                    f"Hostname contains '{word}'"
                ]
            }

    # Printer
    if 9100 in open_ports:
        return {
            "icon": "🖨️",
            "type": "Network Printer",
            "confidence": "HIGH",
            "score": 90,
            "reasons": [
                "Printer service detected"
            ]
        }

    # Chromecast
    if 8008 in open_ports or 8009 in open_ports:
        return {
            "icon": "📺",
            "type": "Streaming Device",
            "confidence": "HIGH",
            "score": 90,
            "reasons": [
                "Chromecast service detected"
            ]
        }

    # Apple
    if 62078 in open_ports:
        return {
            "icon": "📱",
            "type": "Apple Device",
            "confidence": "MEDIUM",
            "score": 70,
            "reasons": [
                "Apple-related service detected"
            ]
        }

    # Generic web device
    if 80 in open_ports or 443 in open_ports:
        return {
            "icon": "🌐",
            "type": "Network Device",
            "confidence": "LOW",
            "score": 30,
            "reasons": [
                "Web service detected"
            ]
        }

    # Unknown
    return {
        "icon": "❓",
        "type": "Unknown Device",
        "confidence": "LOW",
        "score": 0,
        "reasons": [
            "Not enough identifying information"
        ]
    }


# ============================================================
# FIND LOCAL NETWORK
# ============================================================

def get_network():

    # macOS
    for interface in ["en0", "en1"]:

        try:
            result = subprocess.run(
                [
                    "ipconfig",
                    "getifaddr",
                    interface
                ],
                capture_output=True,
                text=True
            )

            ip = result.stdout.strip()

            if ip:
                parts = ip.split(".")

                if len(parts) == 4:
                    return ".".join(parts[:3]) + ".0/24"

        except Exception:
            pass

    # Linux fallback
    try:
        result = subprocess.run(
            ["hostname", "-I"],
            capture_output=True,
            text=True
        )

        addresses = result.stdout.split()

        for ip in addresses:

            parts = ip.split(".")

            if len(parts) == 4:
                return ".".join(parts[:3]) + ".0/24"

    except Exception:
        pass

    return None


# ============================================================
# NETWORK SCANNER
# ============================================================

def scan_network(network):

    print(f"Scanning {network}...")

    packet = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        /
        ARP(pdst=network)
    )

    answered = srp(
        packet,
        timeout=4,
        verbose=False
    )[0]

    devices = []

    for _, response in answered:

        ip = response.psrc
        mac = response.hwsrc

        print(f"Checking {ip}...")

        hostname = get_hostname(ip)
        open_ports = scan_ports(ip)

        identification = identify_device(
            hostname,
            open_ports
        )

        services = [
            PORTS[port]
            for port in open_ports
        ]

        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "type": identification["type"],
            "icon": identification["icon"],
            "confidence": identification["confidence"],
            "score": identification["score"],
            "reasons": identification["reasons"],
            "ports": open_ports,
            "services": services
        })

    # Cameras first
    devices.sort(
        key=lambda d: (
            0 if "Camera" in d["type"] else 1,
            -d["score"]
        )
    )

    return devices


# ============================================================
# HOMEPAGE
# ============================================================

@app.route("/")
def index():

    return send_from_directory(
        os.path.dirname(os.path.abspath(__file__)),
        "index.html"
    )


# ============================================================
# SCAN API
# ============================================================

@app.route("/scan")
def scan():

    network = get_network()

    if not network:
        return jsonify({
            "error": "Could not determine your local network."
        }), 500

    try:

        devices = scan_network(network)

        camera_count = sum(
            1
            for device in devices
            if "Camera" in device["type"]
        )

        return jsonify({
            "network": network,
            "devices": devices,
            "count": len(devices),
            "camera_count": camera_count
        })

    except Exception as error:

        return jsonify({
            "error": str(error)
        }), 500


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print()
    print("======================================")
    print("       CAMERA NETWORK SCANNER")
    print("======================================")
    print()
    print("Open your browser at:")
    print("http://127.0.0.1:5000")
    print()
    print("Keep this Terminal window open.")
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
