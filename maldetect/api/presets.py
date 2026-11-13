"""Demo feature profiles offered by the scan form.

Profiles are written against the dataset's column names, which are fixed, and
translated to API slugs through the feature catalog. ``expected`` is a hint
for the UI about the kind of app being illustrated, not a promised verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from maldetect import features as catalog


@dataclass(frozen=True)
class PresetSpec:
    id: str
    name: str
    description: str
    expected: str
    keys: tuple[str, ...]


PRESET_SPECS: tuple[PresetSpec, ...] = (
    PresetSpec(
        id="sms_fraud_trojan",
        name="SMS fraud trojan",
        description=(
            "Sends premium-rate texts, hides the confirmation replies from the user "
            "and fingerprints the handset."
        ),
        expected="malicious",
        keys=(
            "TelephonyManager.*getDeviceId",
            "TelephonyManager.*getSubscriberId",
            "abortBroadcast",
            "SEND_SMS",
            "RECEIVE_SMS",
            "READ_SMS",
            "PHONE_STATE",
            "android.intent.action.BOOT_COMPLETED",
            "INTERNET",
            "ACCESS_NETWORK_STATE",
        ),
    ),
    PresetSpec(
        id="spyware",
        name="Spyware / stalkerware",
        description=(
            "Starts at boot and quietly collects messages, location, camera and "
            "device identifiers for upload to a remote server."
        ),
        expected="malicious",
        keys=(
            "TelephonyManager.*getDeviceId",
            "TelephonyManager.*getSubscriberId",
            "PHONE_STATE",
            "READ_SMS",
            "RECEIVE_SMS",
            "CAMERA",
            "ACCESS_FINE_LOCATION",
            "CALL_PHONE",
            "android.intent.action.BOOT_COMPLETED",
            "Ljava.net.InetSocketAddress",
            "INTERNET",
            "ACCESS_NETWORK_STATE",
            "ACCESS_WIFI_STATE",
        ),
    ),
    PresetSpec(
        id="rooting_dropper",
        name="Rooting dropper",
        description=(
            "Fingerprints the device, fetches a payload over a raw socket, runs root shell "
            "commands to remount the system partition and silently installs further packages."
        ),
        expected="malicious",
        keys=(
            "chown",
            "chmod",
            "mount",
            ".apk",
            ".zip",
            ".dex",
            ".so",
            "System.*loadLibrary",
            "io.File.*delete(",
            "INSTALL_PACKAGES",
            "DELETE_PACKAGES",
            "TelephonyManager.*getDeviceId",
            "TelephonyManager.*getSubscriberId",
            "Ljava.net.InetSocketAddress",
            "android.intent.action.BOOT_COMPLETED",
            "INTERNET",
            "ACCESS_NETWORK_STATE",
        ),
    ),
    PresetSpec(
        id="flashlight_utility",
        name="Flashlight utility",
        description="A single-purpose torch app that only needs the camera flash.",
        expected="benign",
        keys=("CAMERA",),
    ),
    PresetSpec(
        id="messaging_app",
        name="Messaging app",
        description=(
            "A chat client with network access, media capture, Bluetooth headset "
            "support and native media codecs."
        ),
        expected="benign",
        keys=(
            "INTERNET",
            "ACCESS_NETWORK_STATE",
            "ACCESS_WIFI_STATE",
            "CAMERA",
            "BLUETOOTH",
            ".so",
            "System.*loadLibrary",
        ),
    ),
    PresetSpec(
        id="camera_app",
        name="Camera app",
        description=(
            "A photo app that geotags pictures and uses a native image-processing library."
        ),
        expected="benign",
        keys=(
            "CAMERA",
            "ACCESS_FINE_LOCATION",
            "INTERNET",
            ".so",
            "System.*loadLibrary",
        ),
    ),
)


@lru_cache(maxsize=1)
def build_presets() -> tuple[dict[str, Any], ...]:
    """Resolve every preset to a full ``slug -> 0/1`` vector.

    Raises ``RuntimeError`` if a preset names a column the catalog does not
    know, so a catalog change cannot silently ship broken demo data.
    """
    slug_by_key = {feature.key: feature.slug for feature in catalog.FEATURES}
    presets: list[dict[str, Any]] = []
    for spec in PRESET_SPECS:
        missing = [key for key in spec.keys if key not in slug_by_key]
        if missing:
            raise RuntimeError(f"Preset '{spec.id}' references unknown features: {missing}")
        if spec.expected not in ("malicious", "benign"):
            raise RuntimeError(f"Preset '{spec.id}' has an invalid expected verdict")
        enabled = {slug_by_key[key] for key in spec.keys}
        presets.append(
            {
                "id": spec.id,
                "name": spec.name,
                "description": spec.description,
                "expected": spec.expected,
                "features": {
                    feature.slug: int(feature.slug in enabled) for feature in catalog.FEATURES
                },
            }
        )
    return tuple(presets)
