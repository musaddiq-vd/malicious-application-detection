"""Catalog of the 35 static features the detector uses.

Each feature is a yes/no observation about an Android app made without running
it: a permission requested in the manifest, an API or shell command referenced
in the code, a broadcast the app listens for, or a kind of file it mentions.
The catalog is the single source of truth for column names (``key``), API ids
(``slug``) and the human-readable text shown in the dashboard.
"""

from __future__ import annotations

from dataclasses import dataclass

TARGET = "Result"  # 1 = malicious, 0 = benign

CATEGORIES: dict[str, str] = {
    "permission": "Permissions",
    "api_call": "API calls",
    "intent": "Broadcast intents",
    "command": "Shell commands",
    "file_artifact": "File references",
}


@dataclass(frozen=True)
class Feature:
    key: str
    slug: str
    label: str
    category: str
    description: str


FEATURES: tuple[Feature, ...] = (
    Feature(
        "TelephonyManager.*getDeviceId",
        "telephony_get_device_id",
        "Reads device ID (IMEI)",
        "api_call",
        "Calls TelephonyManager.getDeviceId() to read the phone's unique hardware ID, which "
        "malware uses to fingerprint victims and register them with a command server.",
    ),
    Feature(
        "TelephonyManager.*getSubscriberId",
        "telephony_get_subscriber_id",
        "Reads subscriber ID (IMSI)",
        "api_call",
        "Calls TelephonyManager.getSubscriberId() to read the SIM's subscriber identity, which "
        "reveals the carrier and country and is a staple of premium-SMS fraud and spyware.",
    ),
    Feature(
        "abortBroadcast",
        "abort_broadcast",
        "Suppresses broadcasts (abortBroadcast)",
        "api_call",
        "Calls abortBroadcast(), which lets a high-priority receiver swallow an incoming SMS "
        "before the user's messaging app sees it, hiding billing confirmations and bank codes.",
    ),
    Feature(
        "SEND_SMS",
        "send_sms",
        "Can send SMS",
        "permission",
        "Requests SEND_SMS, allowing the app to send text messages without user interaction, "
        "the mechanism behind premium-rate SMS fraud and SMS worms.",
    ),
    Feature(
        "DELETE_PACKAGES",
        "delete_packages",
        "Can uninstall other apps",
        "permission",
        "Requests DELETE_PACKAGES, a system-level permission to remove apps, which malware "
        "wants in order to uninstall security tools or competing malware.",
    ),
    Feature(
        "PHONE_STATE",
        "read_phone_state",
        "Reads phone state and identity",
        "permission",
        "Requests READ_PHONE_STATE, which exposes the phone number, device IDs and call status; "
        "common in legitimate apps but requested by nearly all malware in this dataset.",
    ),
    Feature(
        "RECEIVE_SMS",
        "receive_sms",
        "Can intercept incoming SMS",
        "permission",
        "Requests RECEIVE_SMS so the app is notified of every incoming text, which enables "
        "stealing one-time passwords and receiving commands over SMS.",
    ),
    Feature(
        "Ljava.net.InetSocketAddress",
        "inet_socket_address",
        "Opens raw network sockets",
        "api_call",
        "References java.net.InetSocketAddress, meaning the app builds low-level socket "
        "connections itself, a pattern typical of custom command-and-control channels.",
    ),
    Feature(
        "READ_SMS",
        "read_sms",
        "Can read stored SMS",
        "permission",
        "Requests READ_SMS to read the whole message inbox, giving access to private "
        "conversations, banking alerts and verification codes.",
    ),
    Feature(
        "android.intent.action.BOOT_COMPLETED",
        "boot_completed",
        "Starts automatically at boot",
        "intent",
        "Listens for BOOT_COMPLETED so its code runs every time the phone starts, the standard "
        "way for malware to stay persistent without the user opening the app.",
    ),
    Feature(
        "io.File.*delete(",
        "file_delete",
        "Deletes files",
        "api_call",
        "Calls java.io.File.delete(), which is ordinary housekeeping in most apps but is also "
        "how malware removes its dropped payloads and other traces.",
    ),
    Feature(
        "chown",
        "chown",
        "Uses chown command",
        "command",
        "Contains the shell command chown, which changes file ownership and is practically "
        "only useful to an app that expects to run with root privileges.",
    ),
    Feature(
        "chmod",
        "chmod",
        "Uses chmod command",
        "command",
        "Contains the shell command chmod, used to make a dropped file executable before "
        "running it, a routine step in root exploits and payload droppers.",
    ),
    Feature(
        "mount",
        "mount",
        "Uses mount command",
        "command",
        "Contains the shell command mount, which rooting malware uses to remount the read-only "
        "system partition as writable so it can install itself permanently.",
    ),
    Feature(
        ".apk",
        "ref_apk",
        "References APK files",
        "file_artifact",
        "Contains the string '.apk', suggesting the app handles other application packages, "
        "as droppers do when they download or unpack a second-stage app.",
    ),
    Feature(
        ".zip",
        "ref_zip",
        "References ZIP archives",
        "file_artifact",
        "Contains the string '.zip', indicating the app works with archives, which can hide "
        "bundled or downloaded payloads from simple scanners.",
    ),
    Feature(
        ".dex",
        "ref_dex",
        "References DEX bytecode files",
        "file_artifact",
        "Contains the string '.dex', a sign the app may load extra Dalvik bytecode at runtime "
        "so that its real behaviour is not visible in the code that was reviewed.",
    ),
    Feature(
        "CAMERA",
        "camera",
        "Can use the camera",
        "permission",
        "Requests CAMERA, which lets the app take photos and record video and can be abused "
        "by spyware for covert surveillance.",
    ),
    Feature(
        "ACCESS_FINE_LOCATION",
        "access_fine_location",
        "Can read precise GPS location",
        "permission",
        "Requests ACCESS_FINE_LOCATION for GPS-accurate positioning, which is needed by maps "
        "and ride apps but also lets spyware track a victim's movements.",
    ),
    Feature(
        "INSTALL_PACKAGES",
        "install_packages",
        "Can silently install apps",
        "permission",
        "Requests INSTALL_PACKAGES, a system-level permission to install apps without a "
        "prompt, which droppers seek in order to add more malware silently.",
    ),
    Feature(
        "android.intent.action.BATTERY_LOW",
        "battery_low",
        "Reacts to low battery",
        "intent",
        "Listens for the BATTERY_LOW broadcast, which malware sometimes uses as an extra "
        "wake-up trigger or to pause noisy activity so the user does not notice the drain.",
    ),
    Feature(
        ".so",
        "ref_so",
        "References native libraries (.so)",
        "file_artifact",
        "Contains the string '.so', meaning the app ships or loads native shared libraries, "
        "where exploit code and logic hidden from Java-level analysis usually live.",
    ),
    Feature(
        "android.intent.action.ACTION_POWER_CONNECTED",
        "power_connected",
        "Reacts to charger being connected",
        "intent",
        "Listens for ACTION_POWER_CONNECTED, a frequent system event that malware registers "
        "for as a reliable trigger to restart its background service.",
    ),
    Feature(
        "System.*loadLibrary",
        "load_library",
        "Loads native code (System.loadLibrary)",
        "api_call",
        "Calls System.loadLibrary() to run native code, which is normal for games and media "
        "apps but also the entry point for root exploits and packed payloads.",
    ),
    Feature(
        ".exe",
        "ref_exe",
        "References Windows executables (.exe)",
        "file_artifact",
        "Contains the string '.exe', which would point to cross-platform malware that drops "
        "Windows programs onto connected PCs; no app in the training data has it.",
    ),
    Feature(
        "ACCESS_NETWORK_STATE",
        "access_network_state",
        "Checks network connectivity",
        "permission",
        "Requests ACCESS_NETWORK_STATE to see whether the device is online, which is harmless "
        "on its own but lets malware wait for a connection before contacting its server.",
    ),
    Feature(
        "BLUETOOTH",
        "bluetooth",
        "Can use Bluetooth",
        "permission",
        "Requests BLUETOOTH to talk to paired devices; in this dataset it is slightly more "
        "common in benign apps, so it tends to count as mild evidence of legitimacy.",
    ),
    Feature(
        "ACCESS_WIFI_STATE",
        "access_wifi_state",
        "Reads Wi-Fi information",
        "permission",
        "Requests ACCESS_WIFI_STATE, exposing the Wi-Fi network name and the device MAC "
        "address, which can be used for fingerprinting and rough location tracking.",
    ),
    Feature(
        "BROADCAST_SMS",
        "broadcast_sms",
        "Can forge SMS-received broadcasts",
        "permission",
        "Requests BROADCAST_SMS, a system-only permission to announce that an SMS arrived, "
        "which would allow fake incoming messages to be injected into other apps.",
    ),
    Feature(
        "CALL_PHONE",
        "call_phone",
        "Can place phone calls",
        "permission",
        "Requests CALL_PHONE, letting the app dial numbers without the user confirming, "
        "which is how premium-rate call fraud is carried out.",
    ),
    Feature(
        "CALL_PRIVILEGED",
        "call_privileged",
        "Can call any number, including emergency",
        "permission",
        "Requests CALL_PRIVILEGED, a system-only permission normally granted to preinstalled "
        "dialer apps, which is why it appears almost exclusively in benign samples here.",
    ),
    Feature(
        "CLEAR_APP_CACHE",
        "clear_app_cache",
        "Can clear all app caches",
        "permission",
        "Requests CLEAR_APP_CACHE to wipe the cached data of every app, a permission used by "
        "cleaner utilities and equally rare in benign and malicious samples.",
    ),
    Feature(
        "CLEAR_APP_USER_DATA",
        "clear_app_user_data",
        "Can wipe other apps' data",
        "permission",
        "Requests CLEAR_APP_USER_DATA, a system-only permission to erase another app's "
        "storage, seen mostly in preinstalled system tools rather than malware.",
    ),
    Feature(
        "CONTROL_LOCATION_UPDATES",
        "control_location_updates",
        "Can control location update reporting",
        "permission",
        "Requests CONTROL_LOCATION_UPDATES, a system-only permission over radio location "
        "notifications that is so rare it carries almost no signal either way.",
    ),
    Feature(
        "INTERNET",
        "internet",
        "Has internet access",
        "permission",
        "Requests INTERNET, which most apps need, but malware requests it almost universally "
        "because stolen data and remote commands must travel over the network.",
    ),
)

_BY_SLUG: dict[str, Feature] = {f.slug: f for f in FEATURES}
_BY_KEY: dict[str, Feature] = {f.key: f for f in FEATURES}


def by_slug(slug: str) -> Feature:
    """Return the feature with the given slug; raises KeyError if unknown."""
    return _BY_SLUG[slug]


def by_key(key: str) -> Feature:
    """Return the feature for an exact CSV column name; raises KeyError if unknown."""
    return _BY_KEY[key]


def slugs() -> list[str]:
    """All 35 slugs in CSV column order (the model's input order)."""
    return [f.slug for f in FEATURES]


def keys() -> list[str]:
    """All 35 CSV column names in order."""
    return [f.key for f in FEATURES]
