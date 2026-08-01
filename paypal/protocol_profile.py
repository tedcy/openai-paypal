"""Shared browser identity and runtime settings for pure-protocol flows."""

from __future__ import annotations

from config import BROWSER_PROFILE
from paypal.country import CountryProfile, browser_profile_for


IOS_CRIOS_136_USER_AGENT = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "CriOS/136.0.7103.60 Mobile/15E148 Safari/537.36"
)

PROTOCOL_FINGERPRINT_SOURCE = "random"
PROTOCOL_DATADOME_MODE = "protocol"
PROTOCOL_MTR_RUNTIME = "python_generated"
PROTOCOL_RISK_SIGNALS_MODE = "protocol"
PROTOCOL_TRANSPORT = "curl-chrome-http1"
PROTOCOL_IMPERSONATE = "chrome136"


def build_ios_crios136_protocol_profile(
    country_profile: CountryProfile,
) -> dict[str, object]:
    """Return the coherent mobile identity proven by the cold-protocol runs."""
    return browser_profile_for(
        country_profile,
        {
            **BROWSER_PROFILE,
            "user_agent": IOS_CRIOS_136_USER_AGENT,
            "chrome_major": 136,
            "chrome_full_version": "136.0.7103.60",
            "platform": "iPhone",
            "sec_ch_platform": "",
            "ua_client_hints_enabled": False,
            "preserve_browser_identity": True,
            "mobile": True,
            "hardware_concurrency": 12,
            "device_pixel_ratio": 3,
            "gpu_vendor": "Apple Inc.",
            "gpu_renderer": "Apple GPU",
            "webgl_vendor": "Apple Inc.",
            "webgl_renderer": "Apple GPU",
            "screen": {
                "width": 480,
                "height": 854,
                "availWidth": 480,
                "availHeight": 854,
                "colorDepth": 24,
                "pixelDepth": 24,
            },
            "viewport": {"width": 480, "height": 754},
        },
    )
