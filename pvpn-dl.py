#!/usr/bin/env python3
"""
ProtonVPN WireGuard Configuration Downloader

Downloads WireGuard configurations for ProtonVPN servers using the ProtonVPN API.

Based on: https://gist.github.com/fusetim/1a1ee1bdf821a45361f346e9c7f41e5a

Usage:
    1. Log in to https://account.protonvpn.com in your browser
    2. Open Developer Tools (F12) -> Network tab
    3. Navigate to any page and find a request to the Proton API
    4. Extract from the request:
       - x-pm-uid header value       -> --uid
       - AUTH-<uid> cookie value      -> --auth-token
       - Session-Id cookie value      -> --session-id
       - x-pm-appversion header value -> --app-version (optional)
    5. Run: python pvpn-dl.py --uid YOUR_UID --auth-token YOUR_TOKEN --session-id YOUR_SESSION

    Tip: Look at requests to https://account.proton.me/api/core/v4/events/latest
"""

import argparse
import base64
import hashlib
import http.client
import http.cookies
import json
import os
import sys
import time


def parse_args():
    parser = argparse.ArgumentParser(
        description="Download WireGuard configurations for ProtonVPN servers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download all Plus-tier configs for Switzerland:
  %(prog)s --uid UID --auth-token TOKEN --session-id SID --countries CH

  # Download all free-tier configs:
  %(prog)s --uid UID --auth-token TOKEN --session-id SID --tier 0

  # Download all configs (no country filter):
  %(prog)s --uid UID --auth-token TOKEN --session-id SID

  # List servers without generating configs:
  %(prog)s --uid UID --auth-token TOKEN --session-id SID --list-only

  # Download with P2P feature required:
  %(prog)s --uid UID --auth-token TOKEN --session-id SID --features P2P
        """,
    )

    # Auth
    parser.add_argument("--uid", required=True, help="x-pm-uid header value")
    parser.add_argument(
        "--auth-token", required=True, help="AUTH-<uid> cookie value"
    )
    parser.add_argument(
        "--session-id", required=True, help="Session-Id cookie value"
    )
    parser.add_argument(
        "--app-version",
        default="web-vpn-settings@5.0.2.0",
        help="x-pm-appversion header (default: %(default)s)",
    )

    # Filters
    parser.add_argument(
        "--countries",
        nargs="*",
        default=None,
        help="Country codes to filter by (e.g. CH US NL). Default: all countries",
    )
    parser.add_argument(
        "--tier",
        type=int,
        default=None,
        help="Server tier: 0=Free, 1=Basic, 2=Plus. Default: all tiers",
    )
    parser.add_argument(
        "--features",
        nargs="*",
        default=[],
        help='Required features (P2P, TOR, SecureCore, XOR, IPv6). '
             'Prefix with - to exclude (e.g. -TOR)',
    )
    parser.add_argument(
        "--max-servers",
        type=int,
        default=0,
        help="Maximum number of configs to generate (0 = unlimited)",
    )

    # Config options
    parser.add_argument(
        "--prefix",
        default="pvpn",
        help="Prefix for config filenames and device names (default: %(default)s)",
    )
    parser.add_argument(
        "--output-dir",
        default="./configs",
        help="Output directory for config files (default: %(default)s)",
    )
    parser.add_argument(
        "--list-only",
        action="store_true",
        help="Only list matching servers, don't generate configs",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=5.0,
        help="Delay in seconds between API requests to avoid rate limiting (default: %(default)s)",
    )

    # WireGuard feature flags
    parser.add_argument("--split-tcp", action="store_true", default=True)
    parser.add_argument("--no-split-tcp", action="store_false", dest="split_tcp")
    parser.add_argument("--port-forwarding", action="store_true", default=True)
    parser.add_argument(
        "--no-port-forwarding", action="store_false", dest="port_forwarding"
    )
    parser.add_argument("--safe-mode", action="store_true", default=False)
    parser.add_argument("--random-nat", action="store_true", default=False)
    parser.add_argument(
        "--netshield-level",
        type=int,
        default=0,
        choices=[0, 1, 2],
        help="NetShield level: 0=off, 1=block malware, 2=block malware+ads (default: 0)",
    )

    return parser.parse_args()


class ProtonVPNClient:
    """Client for the ProtonVPN API to download WireGuard configurations."""

    API_HOST = "account.protonvpn.com"

    # Server feature bitmask constants
    FEATURE_SECURE_CORE = 1
    FEATURE_TOR = 2
    FEATURE_P2P = 4
    FEATURE_XOR = 8
    FEATURE_IPV6 = 16

    FEATURE_MAP = {
        "SecureCore": FEATURE_SECURE_CORE,
        "TOR": FEATURE_TOR,
        "P2P": FEATURE_P2P,
        "XOR": FEATURE_XOR,
        "IPv6": FEATURE_IPV6,
    }

    def __init__(self, uid, auth_token, session_id, app_version, delay=5.0):
        self.uid = uid
        self.delay = delay
        self.connection = http.client.HTTPSConnection(self.API_HOST)

        cookie = http.cookies.SimpleCookie()
        cookie["AUTH-" + uid] = auth_token
        cookie["Session-Id"] = session_id

        self.headers = {
            "x-pm-appversion": app_version,
            "x-pm-uid": uid,
            "Accept": "application/vnd.protonmail.v1+json",
            "Cookie": cookie.output(attrs=[], header="", sep="; "),
        }

    def _request(self, method, path, body=None):
        """Make an API request with rate limiting and error handling."""
        time.sleep(self.delay)

        h = self.headers.copy()
        if body is not None:
            h["Content-Type"] = "application/json"
            self.connection.request(method, path, body=json.dumps(body), headers=h)
        else:
            self.connection.request(method, path, headers=h)

        response = self.connection.getresponse()
        data = response.read().decode()

        if response.status != 200:
            print(
                f"  API error: {response.status} {response.reason}",
                file=sys.stderr,
            )
            if response.status == 429:
                print(
                    "  Rate limited! Increase --delay and try again.",
                    file=sys.stderr,
                )
            return None

        return json.loads(data)

    def get_servers(self):
        """Fetch the list of all logical VPN servers."""
        print("Fetching server list...")
        resp = self._request("GET", "/api/vpn/logicals")
        if resp is None:
            print("Failed to fetch server list.", file=sys.stderr)
            sys.exit(1)
        servers = resp.get("LogicalServers", [])
        print(f"Found {len(servers)} servers.")
        return servers

    def generate_keys(self):
        """Generate a WireGuard key pair via the API."""
        resp = self._request("GET", "/api/vpn/v1/certificate/key/EC")
        if resp is None:
            return None

        full_priv = resp["PrivateKey"]
        pub = resp["PublicKey"].split("\n")[1]
        priv = resp["PrivateKey"].split("\n")[1]
        return (full_priv, pub, priv)

    def register_config(self, server, keys, prefix, config_features):
        """Register a WireGuard configuration with the API."""
        entry = server["Servers"][0]
        has_p2p = server["Features"] & self.FEATURE_P2P == self.FEATURE_P2P

        body = {
            "ClientPublicKey": keys[1],  # pub
            "Mode": "persistent",
            "DeviceName": f"{prefix}-{server['Name']}",
            "Features": {
                "peerName": server["Name"],
                "peerIp": entry["EntryIP"],
                "peerPublicKey": entry["X25519PublicKey"],
                "platform": "Windows",
                "SafeMode": config_features["SafeMode"],
                "SplitTCP": config_features["SplitTCP"],
                "PortForwarding": config_features["PortForwarding"] if has_p2p else False,
                "RandomNAT": config_features["RandomNAT"],
                "NetShieldLevel": config_features["NetShieldLevel"],
            },
        }

        return self._request("POST", "/api/vpn/v1/certificate", body=body)

    def close(self):
        self.connection.close()

    @staticmethod
    def derive_wireguard_private_key(keys):
        """Derive WireGuard x25519 private key from the EC private key."""
        raw = base64.b64decode(keys[2])[-32:]
        hash_bytes = list(hashlib.sha512(raw).digest())[:32]
        hash_bytes[0] &= 0xF8
        hash_bytes[31] &= 0x7F
        hash_bytes[31] |= 0x40
        return base64.b64encode(bytes(hash_bytes)).decode()

    @staticmethod
    def build_config(prefix, keys, registration):
        """Build a WireGuard config file string."""
        wg_priv = ProtonVPNClient.derive_wireguard_private_key(keys)
        feat = registration["Features"]
        return (
            f"[Interface]\n"
            f"# Key for {prefix}\n"
            f"PrivateKey = {wg_priv}\n"
            f"Address = 10.2.0.2/32\n"
            f"DNS = 10.2.0.1\n"
            f"\n"
            f"[Peer]\n"
            f"# {feat['peerName']}\n"
            f"PublicKey = {feat['peerPublicKey']}\n"
            f"AllowedIPs = 0.0.0.0/0\n"
            f"Endpoint = {feat['peerIp']}:51820\n"
        )


def get_feature_list(bitmask):
    """Convert a feature bitmask to a list of feature strings."""
    features = []
    for name, bit in ProtonVPNClient.FEATURE_MAP.items():
        if bitmask & bit:
            features.append(name)
        else:
            features.append(f"-{name}")
    return features


def server_matches_filters(server, countries, tier, required_features):
    """Check if a server matches the given filters."""
    if countries is not None:
        if (
            server["EntryCountry"] not in countries
            and server["ExitCountry"] not in countries
        ):
            return False

    if tier is not None and server["Tier"] != tier:
        return False

    if required_features:
        feat = get_feature_list(server["Features"])
        for rf in required_features:
            if rf not in feat:
                return False

    return True


def print_server_info(server):
    """Print detailed info about a server."""
    f = server["Features"]
    print(f"  - Server {server['Name']}")
    print(f"    ID: {server['ID']}")
    print(f"    Entry: {server['EntryCountry']}  Exit: {server['ExitCountry']}")
    print(f"    Tier: {server['Tier']}")
    print(f"    Features: ", end="")
    labels = []
    for name, bit in ProtonVPNClient.FEATURE_MAP.items():
        if f & bit:
            labels.append(name)
    print(", ".join(labels) if labels else "None")
    print(f"    Score: {server['Score']:.4f}  Load: {server['Load']}%  Status: {server['Status']}")
    for inst in server["Servers"]:
        print(f"    Instance {inst.get('Label', '?')}: {inst['EntryIP']} -> {inst['ExitIP']}  ({inst['Domain']})")


def main():
    args = parse_args()

    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)

    client = ProtonVPNClient(
        uid=args.uid,
        auth_token=args.auth_token,
        session_id=args.session_id,
        app_version=args.app_version,
        delay=args.delay,
    )

    config_features = {
        "SafeMode": args.safe_mode,
        "SplitTCP": args.split_tcp,
        "PortForwarding": args.port_forwarding,
        "RandomNAT": args.random_nat,
        "NetShieldLevel": args.netshield_level,
    }

    try:
        servers = client.get_servers()
    except Exception as e:
        print(f"Error fetching servers: {e}", file=sys.stderr)
        sys.exit(1)

    # Sort by score (lower is better)
    servers.sort(key=lambda s: s.get("Score", 999))

    matched = [
        s
        for s in servers
        if server_matches_filters(s, args.countries, args.tier, args.features)
    ]

    print(f"\n{len(matched)} servers match your filters.\n")

    if not matched:
        print("No servers matched. Try adjusting your filters.")
        client.close()
        return

    generated = 0
    failed = 0

    for server in matched:
        print_server_info(server)

        if args.list_only:
            continue

        # Generate keys
        keys = client.generate_keys()
        if keys is None:
            print(f"    FAILED to generate keys, skipping.")
            failed += 1
            continue

        # Register config
        reg = client.register_config(server, keys, args.prefix, config_features)
        if reg is None:
            print(f"    FAILED to register config, skipping.")
            failed += 1
            continue

        # Build and write config
        config = ProtonVPNClient.build_config(args.prefix, keys, reg)
        device_name = reg.get("DeviceName", f"{args.prefix}-{server['Name']}")
        filename = f"{device_name}.conf"
        filepath = os.path.join(args.output_dir, filename)

        with open(filepath, "w") as f:
            f.write(config)

        print(f"    -> Saved: {filepath}")
        generated += 1

        if args.max_servers > 0 and generated >= args.max_servers:
            print(f"\nReached max-servers limit ({args.max_servers}).")
            break

    client.close()

    if not args.list_only:
        print(f"\nDone! Generated {generated} configs, {failed} failed.")
        print(f"Configs saved to: {os.path.abspath(args.output_dir)}")
    else:
        print(f"\nListing complete. {len(matched)} servers matched.")


if __name__ == "__main__":
    main()
