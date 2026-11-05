import subprocess
import time
import json
import urllib.error
import urllib.parse
import urllib.request
from ipaddress import ip_address

from prometheus_client import Gauge
from fastapi.exceptions import HTTPException
from logger import *
from settings import *


class MetricsCollector:
    def __init__(self, wg_path):
        self.wg_path = self.check_wg_path(wg_path)

        self.labels = ["interface", "public_key", "endpoint", "allowed_ips", "name"]
        self.handshake_gauge = Gauge(
            "wireguard_latest_handshake_timestamp",
            "Wireguard latest handshake timestamp",
            self.labels,
        )
        self.received_gauge = Gauge(
            "wireguard_bits_received", "Wireguard bits received", self.labels
        )
        self.sent_gauge = Gauge(
            "wireguard_bits_sent", "Wireguard bits sent", self.labels
        )
        self.active_gauge = Gauge(
            "wireguard_peer_active",
            "Whether the Wireguard peer was active in the last 2 minutes",
            self.labels,
        )
        self.location_labels = self.labels + ["latitude", "longitude"]
        self.location_gauge = Gauge(
            "wireguard_peer_location",
            "Geographic location of a Wireguard peer endpoint",
            self.location_labels,
        )

        self.last_labels = {}
        self.last_location_labels = {}
        self.names = {}
        self.geolocation_cache = {}

    @staticmethod
    def check_wg_path(wg_path):
        if not os.path.exists(wg_path):
            logger.exception(f"File {wg_path} does not exist")
            raise HTTPException(
                status_code=500, detail=f"File {wg_path} does not exist"
            )
        return wg_path

    def collect_metrics(self):
        output = self.execute_wg_command()
        peers = self.extract_metrics_from_wg_output(output)
        self.set_gauge_values(peers)

    def execute_wg_command(self):
        try:
            output = (
                subprocess.check_output([self.wg_path, "show", "all", "dump"])
                .decode()
                .strip()
            )
        except subprocess.CalledProcessError as e:
            logger.exception(f"Failed to get Wireguard metrics: {e}")
            raise HTTPException(
                status_code=500, detail=f"Failed to get Wireguard metrics: {e}"
            )
        return output

    def extract_metrics_from_wg_output(self, output):
        peers = {
            fields[1]: {
                "interface": fields[0],
                "public_key": fields[1],
                "name": self.find_config_file(fields[1]),
                "endpoint": self.extract_endpoint_host(fields[3]),
                "allowed_ips": fields[4],
                "active": (
                    1
                    if len(fields) > 5 and (time.time() - int(fields[5])) <= 125
                    else 0
                ),
                "last_handshake": int(fields[5]) if len(fields) > 5 else 0,
                "received": int(fields[6]) if len(fields) > 6 else 0,
                "sent": int(fields[7]) if len(fields) > 7 else 0,
            }
            for fields in (line.split("\t") for line in output.split("\n")[1:])
        }
        return list(peers.values())

    def set_gauge_values(self, peers):
        for peer in peers:
            labels = [peer[label] for label in self.labels]

            last_labels = self.last_labels.get(peer["public_key"], {})
            if last_labels and labels != last_labels.get("labels"):
                self.handshake_gauge.remove(*last_labels.get("labels"))
                self.received_gauge.remove(*last_labels.get("labels"))
                self.sent_gauge.remove(*last_labels.get("labels"))
                self.active_gauge.remove(*last_labels.get("labels"))

            location = self.geolocate_endpoint(peer["endpoint"])
            last_location_labels = self.last_location_labels.get(peer["public_key"])
            if last_location_labels and (
                not location or last_location_labels != labels + list(location)
            ):
                self.location_gauge.remove(*last_location_labels)

            self.handshake_gauge.labels(*labels).set(peer["last_handshake"])
            self.received_gauge.labels(*labels).set(peer["received"])
            self.sent_gauge.labels(*labels).set(peer["sent"])
            self.active_gauge.labels(*labels).set(peer["active"])
            if location:
                location_labels = labels + list(location)
                self.location_gauge.labels(*location_labels).set(1)
                self.last_location_labels[peer["public_key"]] = location_labels
            else:
                self.last_location_labels.pop(peer["public_key"], None)

            self.last_labels[peer["public_key"]] = {"labels": labels}

    def geolocate_endpoint(self, endpoint):
        if not endpoint:
            return None

        try:
            ip = ip_address(endpoint)
        except ValueError:
            logger.warning(f"Skipping geolocation for invalid endpoint: {endpoint}")
            return None

        if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_reserved:
            return None

        now = time.time()
        cached = self.geolocation_cache.get(endpoint)
        if cached and now - cached["timestamp"] < cached["ttl"]:
            return cached["location"]

        url = GEOLOCATION_API_URL.format(ip=urllib.parse.quote(endpoint, safe=""))
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                result = json.load(response)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            logger.warning(f"Failed to geolocate endpoint {endpoint}: {error}")
            self.geolocation_cache[endpoint] = {
                "location": None,
                "timestamp": now,
                "ttl": GEOLOCATION_FAILURE_CACHE_TTL,
            }
            return None

        if result.get("status") != "success":
            logger.warning(
                f'Geolocation failed for endpoint {endpoint}: {result.get("message", "unknown error")}'
            )
            location = None
        else:
            latitude = result.get("lat")
            longitude = result.get("lon")
            if latitude is None or longitude is None:
                logger.warning(
                    f"Geolocation response had no coordinates for endpoint {endpoint}"
                )
                location = None
            else:
                location = (str(latitude), str(longitude))

        self.geolocation_cache[endpoint] = {
            "location": location,
            "timestamp": now,
            "ttl": GEOLOCATION_CACHE_TTL if location else GEOLOCATION_FAILURE_CACHE_TTL,
        }
        return location

    @staticmethod
    def extract_endpoint_host(endpoint):
        if endpoint == "(none)":
            return ""
        if endpoint.startswith("["):
            return endpoint[1 : endpoint.find("]")]
        if endpoint.count(":") == 1:
            return endpoint.rsplit(":", 1)[0]
        return endpoint

    def find_config_file(self, public_key):
        if public_key in self.names:
            return self.names[public_key]

        with open(os.path.join(CLIENTS_DIR), "r") as f:
            for line in f:
                fields = line.split()
                if public_key == fields[1]:
                    self.names[public_key] = fields[0]
                    return fields[0]

        return ""
