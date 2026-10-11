"""Mac/CLI-parity browser login for the Hermes Index dashboard.

Runs the same `/cli-auth` handshake used by `apps/mac` and `packages/cli`:

1. Bind an ephemeral loopback HTTP listener.
2. Open `{appUrl}/cli-auth?callback=…&version=2&state=…` in the browser.
3. The web app runs the device authorization grant against the owner's browser
   session and redirects to the callback with the approved `device_code`.
4. Redeem that code for this device's own session token and persist it. It
   authenticates as the user; which agent speaks for them is `GET /agents/me`.

Login start returns right away; the frontend polls the status until the
callback lands (or the attempt times out). Only one login runs at a time.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from .env_transport import api_origin, remove_index_env, upsert_index_env

_SESSION_ENV = "INDEX_SESSION_TOKEN"
_CALLBACK_HOST = "127.0.0.1"
_LOGIN_TIMEOUT_SECONDS = 180.0
_DEVICE_CLIENT_ID = "index-device"


def api_root() -> str:
    """Resolve the API root (including its `/api` prefix) for auth calls.

    Shares the transport's resolver so the code approved in the browser is
    redeemed against the same environment every later request uses.
    """
    return api_origin() + "/api"

_lock = threading.Lock()
_session: "_LoginSession | None" = None


def upsert_env_var(name: str, value: str, path: Path | None = None) -> None:
    """Insert or update `NAME=value` in the Hermes `.env`, leaving other vars intact."""
    upsert_index_env(name, value, path)


def remove_env_var(name: str, path: Path | None = None) -> None:
    """Remove every `NAME=` (or `export NAME=`) entry from the Hermes `.env`.

    A leftover Index var on the negotiator profile is removed with it.
    """
    remove_index_env(name, path)


def persist_session_token(token: str) -> None:
    """Persist the device session and the API host that issued it.

    The host has to be stored with the token. A later process that sees only the
    token otherwise calls production with a dev or local session.
    """
    upsert_env_var(_SESSION_ENV, token)
    os.environ[_SESSION_ENV] = token
    from .env_transport import remember_api_origin

    remember_api_origin(api_origin())
    from .transport import reset_transport

    reset_transport()
    from .mcp import sync_index_mcp

    sync_index_mcp()


def clear_session_token() -> None:
    """Remove the persisted session token from the Hermes env file and the process."""
    remove_env_var(_SESSION_ENV)
    os.environ.pop(_SESSION_ENV, None)
    from .mcp import sync_index_mcp

    sync_index_mcp()


def _http_error_detail(exc: urllib.error.HTTPError) -> str:
    """Summarize an error body, preferring the grant's `error_description`."""
    try:
        raw = exc.read().decode("utf-8", errors="replace")[:200].strip()
    except Exception:  # noqa: BLE001 - the status alone is still worth reporting.
        return ""
    if not raw:
        return ""
    try:
        parsed = json.loads(raw)
    except ValueError:
        return f": {raw}"
    if isinstance(parsed, dict):
        described = parsed.get("error_description") or parsed.get("error")
        if described:
            return f": {described}"
    return f": {raw}"


def redeem_device_code(device_code: str) -> tuple[str | None, str | None]:
    """Exchange an approved device code for this device's own session token.

    :param device_code: Code the browser claimed and approved for the owner.
    :returns: `(token, None)` on success, else `(None, reason)`. The reason names
        the endpoint and status, because the common cause is an environment
        answering for a code it never issued.
    """
    endpoint = f"{api_root()}/auth/device/token"
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": _DEVICE_CLIENT_ID,
            }
        ).encode("utf-8"),
        # The session records this request's user agent, and that is what names
        # the device in Index settings.
        headers={"Content-Type": "application/json", "User-Agent": "Index-Hermes"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return None, f"{endpoint} rejected the device code ({exc.code}{_http_error_detail(exc)})."
    except Exception as exc:  # noqa: BLE001 - transport, DNS, or malformed body.
        return None, f"Could not reach {endpoint}: {exc}"
    token = payload.get("access_token") if isinstance(payload, dict) else None
    if isinstance(token, str) and token:
        return token, None
    return None, f"{endpoint} returned no access token."


def revoke_session(token: str) -> bool:
    """Revoke a device session server-side using the session's own token.

    :param token: The session token to revoke.
    :returns: Whether the server confirmed the revocation.
    """
    request = urllib.request.Request(
        f"{api_root()}/auth/sign-out",
        data=b"",
        headers={"Authorization": f"Bearer {token}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return 200 <= response.status < 300
    except Exception:  # noqa: BLE001 - best-effort; local state is cleared anyway.
        return False


# The plsintro wordmark (mark + name), inlined so the page needs nothing from
# the web origin.
_WORDMARK_SVG = """<svg viewBox="0 0 530 112" fill="currentColor" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="plsintro"><path fill-rule="evenodd" clip-rule="evenodd" fill="#0050FF" transform="translate(0 13)" d="M56 0C47.1634 0 40 7.16344 40 16C40 24.8366 47.1634 32 56 32C64.8366 32 72 24.8366 72 16C72 7.16344 64.8366 0 56 0ZM24.7164 31.127C41.3715 31.127 54.8731 44.6286 54.8731 61.2837V86.0001H39.8731V61.2837C39.8731 59.51 39.5685 57.8074 39.0086 56.2255L16.9757 78.2584L6.3691 67.6518L27.6168 46.4042C26.678 46.2222 25.7083 46.127 24.7164 46.127H0V31.127H24.7164ZM87.6567 31.127C71.0016 31.127 57.5 44.6286 57.5 61.2837V86.0001H72.5V61.2837C72.5 59.8942 72.687 58.5485 73.0371 57.2702L96.0851 80.3181L106.692 69.7115L83.644 46.6638C84.9221 46.3138 86.2676 46.127 87.6567 46.127H112.373V31.127H87.6567Z"/><text x="140" y="86" font-family="Inter, -apple-system, system-ui, sans-serif" font-size="100" font-weight="600" textLength="386" lengthAdjust="spacingAndGlyphs">plsintro</text></svg>"""


# The plsintro mark and the Hermes (Nous Research) mark for the "connected"
# row, inlined like the wordmark so the page needs nothing from the network.
_INDEX_MARK_SVG = (
    '<svg viewBox="-6 -19.5 125 125" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M56 0C47.1634 0 40 7.16344 40 16C40 24.8366 47.1634 32 56 32C64.8366 32 72 24.8366 72 16C72 7.16344 64.8366 0 56 0ZM24.7164 31.127C41.3715 31.127 54.8731 44.6286 54.8731 61.2837V86.0001H39.8731V61.2837C39.8731 59.51 39.5685 57.8074 39.0086 56.2255L16.9757 78.2584L6.3691 67.6518L27.6168 46.4042C26.678 46.2222 25.7083 46.127 24.7164 46.127H0V31.127H24.7164ZM87.6567 31.127C71.0016 31.127 57.5 44.6286 57.5 61.2837V86.0001H72.5V61.2837C72.5 59.8942 72.687 58.5485 73.0371 57.2702L96.0851 80.3181L106.692 69.7115L83.644 46.6638C84.9221 46.3138 86.2676 46.127 87.6567 46.127H112.373V31.127H87.6567Z" fill="#0050FF"/></svg>'
)
_HERMES_MARK_SRC = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGAAAABgCAYAAADimHc4AAAV2ElEQVR42t1de5QU1Z3+qnpmeOnwFAYQFBWjSBDFoBiiJhB1ja/dsxxjjBjXXRY3m7gxCmuyZqPG5USJj43PaDBGNlkloqtoUE/CKriIhoAgihs1oPKQN8i7p6r2j/vd0x+Xqu7q7qoZ2D6nz8z0dFXd+t3f8/s9ysOB8fIA+AAiAKHzvwKAQQAGAxgK4FgARwM4HEBvAF14bBHATgBbAXwMYAmAPwD4I4BlAFqdc8Zdq11uvD1fPtcQyGfdSeQTARwF4DP8+0gAnWPOEZCgSa9dAP4XwMsAZgOYB+BTuT7acyO8A4TwXQGcTA7vCGA7gD8D2ABgI7m7AUAzgIEARgAYA+DzQsRAfo+ca+nrAwDPAphOCWlXiWjrDSjwJi2BjgZwPom6l5z6IVWIJX6518kAJgAYD6CTbILeVyTE9Z1NehbAHZQOu74A/w9fLlG+AOAxqoJICB4IwXYAWAHgvwBcDaC/HN/BOd+JAJ4XQodyHvcdUKL0s+lkhri1HtQvz9HPYwA859x8GEOgOAJuAHA3pcUSquCc/zs0tpGzmUnvVrnWRgB/X0Z1HXQvJcxpAGY5RNebj+PakERsFaJGAD6h2lFCqWq5QCQrzSZEzvl/BeDQmHs4qLjeEqMvgPtE5EPnZqt5h47q+E8APRxCNfDnWQC2pVBHUQxTRHRdBx+Mm6CLHU/dHsdl9bx1IxbTRdVrN/LnX9CwB1VsQiTn/gjA8INpEyz39QHw6xwIn0SoVTGEsmu5qsY12HOvBTDkQLcJamjH0M92DVweb1UZH8WoDLsJP61xE+z3P3QM/wFHfOuyXSeLLuZIeJdI9ppLGUV78i4wPlhcpVHWDV4O4CEA3Q40F9UTjrvX8Vzy4nj7+x5Gypao7/H3GY4UFMQLK1ZhD3YLEy0DcAmAfz2Q7IHlsCbetOX6sALhannvTVANPwDwFIDLARwCYCE/vyJhE+6NUUVJ691Ot9kyVDOAOwFcfCCoIk8CoJkVVE6YkqPL/X8rgNtJuECIf7is6XAA4wBsArAaQC9hEqs2+jKYC1Ou6zkAkwCs5AbcDmAuAUGvPVWRNW4/k8Co3I28zSgzSgi20hjCywDcIJ5Jd4EkfAD/DuB1ADfxOzclSMEtosJaqcYCgSeKRE/HARjAY3ry58+53mvaUxXZi17DG7mPbqDLVfbvlQBuFn9c/7/TIXQx5jtW/fya130XwKVcR0eqQOsAROTS5SRwi0iASsFGucaDAH4Ro/9bnJiiGcB8rmkVgMOcgDOTwCkNoBYSgXwKwHcBfE58cI83YH/6AG4EcC4TKqGI7Qre0DGyDl+ODQXr+RMj0xcpbX15bKvkAq7iOoYBuBLAMwDGEvu36y4wOj6GbutCqqt/5noWE8KYyuNsnqCJEjGevzdTLb4iSaQ2gxcaALwGYCKAv6VOfYs/dwmKGQF4gUQIYgKc6fQq/ooeylcBTGbCxH53HXX6+cRmGnn9mcRrbiL4toRcbSXwN9zwe0R9qC0YDWAaJekI/v9HhDYuErT2Vq7tAsYCC4Q5PuRGtBmkbyXlGwC+Rx08jj/PBPDfXNwKqokIwAkk8mkk1sfcjA085mYmVPR1Fs8xicHP0TG254IUBrSVm3ees35rPJfye6sBjOI7Epu1BcBmAE9SineKOrR2aXxb2gKPrt406t6v8adVTd/k/16iGP8NPZNb5BzdqCI68e97AExxrtM75rM4DvsfCcJc3z4QIt2fEB1fJ5K5CcDTAH4fI62vUioXOecOyXR124EC0mexLqfu3ACTQnxbbuo1cutCqoBfcRN28n+gcdtOldINJt/7DzzuJABfpEQNo3ezlmoN5NDOMCnL46nHTyBRCs4m6e89GMXulc8jrsNC2p0BHMd77CbfKfB/vWiUmxzY+3Ami9bmbQvswt9kwuJCLq4DfweAkRTJQVRB11JXrwNwG7nodS7WehprE9TIZgHZbqLxXUkJ+yGAN1JGtDaIGimMYt+daLsiJ76oFqybmrcasic+XdzBuTC51KnkgEMB/Bv9ZIu5LAKwPkXyIxRVUnR0eNxxa6oA+SyRvpOgxu5zrpUUFYcJWbuIjHFIPca4IeX3/k7wkdFc0FBCz3MYtPQW1224iHIQA5BFCSlLFf9IXFf7vZYaJPd0wgjH830cmWazuM1JBPQquOQD6ek9zfW15qF6mqlK1nPHbYAUxnBokDIxngUgV+lt1/I6vTdXzTwkUhqWwZ4q5ZOn16OG/BT/G8XIryd33KNP7jmLL8gxlbASKwGfMH+AlEbMq4GBBtCQfipezKsA3qdhda8bpuRkG1eMpfMQ1KKG/BQ38AWUCp+ihADNq1G6OtNzyst5iKgmT4EpbdlGtbuA8UyzE72DHtKKFEzhcbP6UM3VhJKWO8BWiX0uJVdX+wqpi1czsvRycOXsei/hBhRRyhdPp9PgO9/tRpWbhqOt9H8RdRRMldvdzhKNZh1yRxJ8vZBTjabl7mVUQb352fHEqGzcsl3Uqc2irUkpBR6jfS/L9fuiP7dllFhJMqgrGE8Uc7rGHrrNWxIchDXOBljIe34VOY1N4qF5WakgG0kekgGXl5OyI+h5zIiplM5CBTUy+u7qcK0lYAtMibsS7zAyXrECQe15uqNUPZHpBnR2YOZaxD9KsUFXMOptzUHVecKxST0Jrl73GemvSsFIgdSnVm2I88xt7qG7V0432oDrr4n7/CSlFER1VG9Ucm3t3/1Tusj2+8NrWVulDdhZI/cHREvfpoH1xbfWAlyt678ZwKNCrDAGDghTSlYWntMARsthCjUEgoOZGWJF/LbWYIQtELYJwBkwjRBxdTku5vM8gMdTnH+tU2qedSlMIIn5NRXuX6urW7LyGD1Jei+roahJ308wEn1FUM7HiHLaDNrdIsI2V7CFHtJ7RFiXwzRwLIJJh+7OseArEFBxfor7t9J5erWwhFcBCQ1gktbjxUdGCoMEiu9CmO6TKfRGTiERGwlvLybE3A2mF6yFn78cU62ga97F+GQwffqvcwPDjO3aZjLORRVUsc1NTyDGlEmnjSX2eTXUVv4RpqkuaaO/DZOuHAiTAI8cv3weTNYqLQZ0WRVrDAT+bk2hWp6WWKgS9P3TKlHmVLagkUmQuBsMnRKSx2GqEt6EKdSFlI4obmQJemdCnac9528IBsZJrc9zN8CkSNOoyaCKz+1n82AS/+WOt+uekzVqYKXgTKnLD528ayBpvl4o1WI+JFUGXszGNgA4m8fOlKrqIOZG76aq6Ziwvq9WYaeW83y3wmTZKhWNfSRtVUEFadGiscw34QaniOoR6UKxIngXTKnJC/z9Mep21+UtSIXDLOr+dbK5IY3vZOYgrJfxFedcBQHb0nD4NJi6otN5riFUgy+UKSxupWTvSWGEI5QqPfw86v+nOC7jhDKNdVtpwMuV8jUS7ijAVCVEUl/0ktiLCMD1lJpCDRJg1/YBSlXV9v2KVD2EZdzRP1VwRy0TfitrO+DGBpej1Hr0LZgCp0C44HfU3XZhPy+zAQVpPx0tMcc6AF+CSaivg6lD7Rgj2gWBMqpxFMIqDHYEk8D/bUo78B/VuKJ+lfi9T7UyAqZC+Wq6amNoAzz6+bMl6n2rjE5sJKFvoyT8gJv3C5hS8Cdhkv8T6Pe7EbAmdtLiU5GTmw7LRK+WPoNERVaCNE5i/JQqQ+bXkEQpwKQSb2GyZhMxn/UodUYuJEfshamcSML6d3ND5wP4MsP5tUQudxGzv01qf5Lgh94pcRgXE/KcWp+ke+5Mj2tNmXXY8x4lJY+5lS16jo4bIL25O2l4Xxe/uJCB6ivnIDyYY2uUVTmvip2qpIYuTXvffh04f6sk4rtR7CwKuoQQxnVSwlHJ0yoIN+rfYQpUNE+Os+c8VrJkXoX1nJZ2PX5Gud3ulIiQ2M5dMFV0exKw+LhQXg154CCm5RI6jRJ1ezkm93uRXtsq1AuBqjlVcsnPiDt6iD7dSP99r1OQlRdn9s0ShazA2f3oASbZNHv9IfxuVInGWQULNgLey3P2TRhPk8cGDKTRjnLcAE+8oc0ppLIrTJFxRabIagMOQ6mm5g4GTw3cmJtz1tFD2mDqlSfeVlCBs0Mpicx9AyIZT2DP9xSjy8l0V3+X0wbYcw2tMU1Zy712oM3ZmbImFZXsQFbhch/x67swauwOU5P5SAx3ZPEKHAloq7bRjjA9El0S1J4vAVkfMmFiDONn4AFB4ISO0jo6FyYBU5Buw6w9k84oNfq11QYcRkarZAe68/7L0tnPgAgdxQg3czNCoqKzJavlZ2hzLLGPpLfRlhvQnKJ4N5Set9zjgGaUuhF9ip4H08R3KjlmkPj4hQyGXthjB1O6wjbYAHv+LmKIK8UDZ1QKJv0MFtSN4mYv8iUZnPF9mFqfSTDdNcc50HW9107jAUU5dA11pstdaX3DYHLXEXKowfKlfF3xkY1USZ2koqLoZLfOkFEAXh1JosdyHgpV7yidCKZZMdHhyUICWhzPpAcMlLyLUeO7MMWxY+kVXQyT6B5WxxosNH5siu++0wazQK2ULSVUoZ+NyctNbnDmRmiBlJ1I+y/EhM4Qrh0mgVu98MeqClmqDQD+MccZRi63PyOJm6JUf3fJw1FocCobio4qOodq5iV6Q2c7YujVqfqGllE9ttzkWZh6oSinEnv3vH+ASVJpmjZAqbLDz6qgVU82w+ECVwpOgEmswJlcUm+RwIVlsHnVvy1O82CeG7CFvv9qhym/m2QH/BTpu2qxeOt2jYApmFpGCfCc6oF6VdBRCR6QbRjcQXVQrAAdZPnqymu96KxtdJK35pfh/N4wmZ04SbBBWFdnprNLiBup/xpyMHiDKwRBc2ESKAE5EzlXVEcSJzzv0Pdkfr5fvOKXOdlUSVz7ZbD4njE63UrBZ6gGWjP0gyOJgsvZEpuL3lIBQs6aMZphhokEZLyITHpsGtVu9evZBJE6Jdyk/d65FUr77ISpnhmPfPSw7wQTVxfvZCzSBFNQtj3nGaa6jvO4vpVO4/fXHDvgxUmA3cXv0ZDsSkDytCkhSbStFPSDmdcQllFFnpMLtkM1vDJwQI8y6udFwh9zYeZYdGlDqEIn+iptLK3GURoiAL6fQLDRMHUwSSIepWzLsef8Nv3/ojPtXEfIaC5YC3XjVFeXBOn0ZV2voDQppS3Uj3UyrLrb5HzHOivLyRRNrgQovlIgvpMEJAU8wSkp+o0B05D9DNHBuHajXrzuWJgirKkwmbT+Ts2/FmJ1KHO9I6SS7kEyQFskbXahVB/l0sQ6K4tgOo+ucWnrlvlt5kF+TGGtT6Qz7SRa/c4bNJCzYMq5l8IUY8V1vKwU0dVZFMegVIeUdP3FMO2pdkN25RgL2HP+War03nBswFJ58sePaWO7xEW2V8qJr0epVakgNfkA8HDKSbRRFaXjqn5sScv7TpIf0kAXxYzLLMKUxXSWYzrC9CxEOcES9pzzUSpSWO/Q532ZyDWen13s6usmmDFiVkVsJae7r/NJoKDKMN99KkarUw+UVHE8h2sryPy6Fc7N6xAlq446ilp6LccN0GmQnnQVaa/Dh5K4uoD3+7DvpNH6E7PfLj7tizDtRGMJql0PUy/f5BhRj4Zvb4rxlwXsW/2W5Bs3cJPO4hoCJmC2w5SLq1735R4uktFoEfGqkTn0kLm2x7rGl4hX5iXYUI9owX7h/U9g6jorlXC748VehaluzhqfD0UlnYxSxcHqhImJVgquofF9OWccSCusTySXb3Wq/KwKst0zl0oZ/n7eygxyWySTsVrlhNrYVpT2pJFieLIGv1qllekc0f/V6ug8A7D3SMP7E8DJpeKZTbYS6jsq5FNi9UWY2vzGmIEVvpy4gd7FORT9UxLcxizSgNZoPUdjthKmfysONNSmvzDnkQzWlZwG05400bmmXdt6qaYYXg7fv5EiNFIejpZkaBdSLXSlK+ka008zLhlvlaaPAbzZtnxiR5Lq2UCo4aMYGrQ6nULNTt/bflHkYB70Jkxn4kSKTyiGbQETD6CUxHWT27bVYsbEXyRuaXfp3Sq20wbYEf5J2Tm7rmupEf5S/rckCZ5+RIzEFcRd+tFD6iPfP4EG29V5IUyz9j11GuVAOm3sXOd+zmj5UdJbVmznRHy52aOjBKeKpGszNhfQj35rJAZmClHSU+nmPSCTpoIYTp0sF8vCK3qTAJsGZDrZcUWFR6m0hSoqZ6AbZOZq4LirsVJwKiWgGg9Dn2g0glmpsI6bWkQ7dJ1EkX4CNN5PEuJZEjao4WFwLj1u5RrnOSPwe1TKCwwV/W4f/VF0nnhhF6kDT4fDPBihVrVgF35VyhSq9mLdUGY+XLnYJozp0InKDKdNu3m7mQ+5TGgYwTyzIFXyu4l4/gcpLrqD3sAhhGNrnaBrj/uEyGFjioY3Xzy5gTD1SMUys4m0yz+JqBvlKdybE57CWomJbienbxbXeB1taVU9ZF25izOYcdrBm9jMxPsDglw+nkFAZm/g0RQdh4rYHg/To7BHHIlWiZDvYMS+JEaVbqMr+Tb19ib+/jC9l0sksk4zGsE+0WmOA41cWU33aNyA7Seo5/vHNElPTTGVvNpu9i8nLNiFyic4dusumOeHrYIZQN6fxF8jYxHsUJEhlLYejFgPhanr/AaZbjXP152MuKvMJth7vgjmCU86guHhWisCPan9tzMiZpErvgJTATevDEIZ1hHmv8UMmIJ5Kr4jmPCJZMTMKBLvARLtGHnYm8WuTqri/k+kNGxgkPrZBEjcluPfSVxNOX8m1WTN+XEv4XFQccn4vTIMY0od7qg9ZhL2bxA/E+bhO/a778I8XAgwhVs2Ef55SeBEMKMQOgkCUHDSpJ6z2Q3SgDJb1MhnqY7dLN96GdEWCec3ZtE16suEkkCItFsekGYv+g7F+vd1bIBWVzRJPuK3cv1tMKXwXWVtY8WT2+SopVoe46XPoXkSpYdDjIu5t8Ax5BOznr/tyxDshYh/GOajdL+OFFQ1rDPAudcxgnakmFZJnys33JEReSQPnkOMCqv2vjtIkDmROI+bgNnLzwc54+6RdX+ATxG/EqYS+ev0RCDP6KolHggTVJGNvj+m3YFAEy3MtzYSJJyBfZ8VXw/x3fvuSZW3h7Zmraz5CcldtMkzZpLQ1e4CGQc1glyzhfizCALeL4CcL7jQj6VtdQH2HS7VlCEXFsT4t1Iqp2Hfxy66hQTI++mqDWLQrK7+YUrdH8bMithNDl8gCe9DnWHiDWIgb2MpC2CaIhQy75rDqGZ73UkoPbNsJ0pzIhrRTq+CuG07UuAoQcLf35eA7gNBQeEUd9mN3sANgvjeK6Ugys+J8XwGonOIyp7Vns8c1sHX71ShelYzsFsuYvygRLLDY1SevcFr+b1vCnSykJt+Tl7z25z1/BP1/n21NmNk+ZTtFvGMggrezXaYMr2r6VrO5Ge/FIN7YQwRfee5kvqI2T5UBUszaghJc99NUiVe1ev/AC4E8r7abBW4AAAAAElFTkSuQmCC"


def _callback_html(title: str, message: str, ok: bool = False) -> str:
    """Callback page in the plsintro site style: off-white, serif title."""
    status = (
        '<span class="tag tag--ok"><span class="dot"></span>connected</span>'
        if ok
        else '<span class="tag tag--fail">&#10005; not connected</span>'
    )
    link = (
        '<div class="link" aria-hidden="true">'
        f'<span class="app app--index">{_INDEX_MARK_SVG}</span>'
        '<span class="wire"><span class="pulse"></span></span>'
        f'<span class="app"><img src="{_HERMES_MARK_SRC}" alt=""></span>'
        "</div>"
        if ok
        else ""
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · plsintro</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Source+Serif+4:opsz,wght@8..60,400&family=Public+Sans:wght@300;400;500&display=swap">
<style>
:root{{--ink:#041729;--bg:#FCFEFB;--body:#2E3B45;--muted:#5E6F7C;--green:#123A00;--rule:rgba(4,23,41,.12);--mono:'SF Mono',Menlo,Consolas,monospace}}
*{{box-sizing:border-box}}
html,body{{margin:0;background:var(--bg);color:var(--ink)}}
body{{min-height:100vh;display:flex;flex-direction:column;font-family:'Public Sans',system-ui,sans-serif;-webkit-font-smoothing:antialiased}}
.col{{width:100%;max-width:836px;margin:0 auto;padding:0 24px}}
.nav{{padding:26px 0;color:var(--ink)}}
.nav svg{{height:22px;width:auto;display:block}}
main{{flex:1;display:flex;align-items:center}}
.c{{display:flex;flex-direction:column;align-items:flex-start;gap:22px;padding:40px 0 12vh}}
.tag{{display:inline-flex;align-items:center;gap:8px;font-family:var(--mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;padding:5px 9px;background:#ECEEEC;color:#3F4C56}}
.tag--ok{{background:#E3F0DE;color:var(--green)}}
.tag--fail{{background:#F6E3E1;color:#9B2C22}}
.dot{{width:6px;height:6px;background:currentColor;animation:blink 1.2s step-end infinite}}
h1{{margin:0;font-family:'Source Serif 4',Georgia,serif;font-weight:400;font-size:40px;line-height:1.2;letter-spacing:-.015em}}
p{{margin:0;max-width:520px;font-size:15px;line-height:1.7;font-weight:300;color:var(--body)}}
.link{{display:flex;align-items:center;gap:0;margin-top:10px}}
.app{{width:48px;height:48px;display:flex;align-items:center;justify-content:center;border:1px solid var(--rule);background:#fff}}
.app svg{{height:24px;width:auto;color:var(--ink)}}
.app img{{width:36px;height:36px;display:block}}
.wire{{position:relative;width:96px;height:1px;background:var(--ink);overflow:hidden}}
.pulse{{position:absolute;top:-2px;left:0;width:18px;height:5px;background:#4091BB;animation:pulse 1.8s ease-in-out infinite}}
footer{{padding:24px 0;font-family:var(--mono);font-size:11px;color:var(--green)}}
@keyframes blink{{0%,49%{{opacity:1}}50%,100%{{opacity:0}}}}
@keyframes pulse{{0%{{transform:translateX(-18px)}}100%{{transform:translateX(96px)}}}}
@media (prefers-reduced-motion:reduce){{.dot,.pulse{{animation:none}}}}
@media (max-width:520px){{h1{{font-size:32px}}}}
</style></head>
<body>
<div class="col"><nav class="nav" aria-label="plsintro">{_WORDMARK_SVG}</nav></div>
<main><div class="col"><div class="c">{status}<h1>{title}</h1><p>{message}</p>{link}</div></div></main>
<div class="col"><footer>plsintro.com</footer></div>
</body></html>"""


class _LoginSession:
    def __init__(self, state: str, server: HTTPServer) -> None:
        self.state = state
        self.server = server
        self.port = server.server_address[1]
        self.status = "pending"  # pending | success | failed
        self.error: str | None = None
        self.device_code: str | None = None
        self.consumed = False
        self.created_at = time.monotonic()

    def expired(self) -> bool:
        return (time.monotonic() - self.created_at) > _LOGIN_TIMEOUT_SECONDS


def _make_handler(session: _LoginSession):
    class _CallbackHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:  # noqa: A003 - silence stdlib logging
            pass

        def _respond(self, code: int, title: str, message: str, ok: bool = False) -> None:
            body = _callback_html(title, message, ok).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
            parsed = urlparse(self.path)
            if parsed.path != "/callback":
                self._respond(404, "Not found", "Unexpected request.")
                return
            params = parse_qs(parsed.query)
            state = (params.get("state") or [None])[0]
            if not session.state or state != session.state:
                self._respond(400, "Authorization failed", "Invalid login state. Return to Hermes and try again.")
                return
            if session.consumed:
                self._respond(409, "Already completed", "This login callback has already been used.")
                return
            session.consumed = True
            device_code = (params.get("device_code") or [None])[0]
            if device_code:
                session.device_code = device_code
                session.status = "success"
                self._respond(200, "Authentication complete", "You can close this tab and return to Hermes.", ok=True)
                return
            session.status = "failed"
            session.error = "No device code was received in the callback."
            self._respond(400, "Authorization failed", "Incomplete sign-in received. Please try again.")

    return _CallbackHandler


def _shutdown_locked() -> None:
    global _session
    if _session is not None:
        try:
            _session.server.shutdown()
            _session.server.server_close()
        except Exception:  # noqa: BLE001 - teardown is best-effort.
            pass
        _session = None


def start_login(app_base_url: str) -> str:
    """Bind a fresh loopback listener and return the `/cli-auth` URL to open."""
    global _session
    state = secrets.token_urlsafe(32)
    server = HTTPServer((_CALLBACK_HOST, 0), BaseHTTPRequestHandler)
    session = _LoginSession(state, server)
    server.RequestHandlerClass = _make_handler(session)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    with _lock:
        _shutdown_locked()
        _session = session
    callback = f"http://{_CALLBACK_HOST}:{session.port}/callback"
    query = urlencode({"callback": callback, "version": "2", "state": state})
    return f"{app_base_url.rstrip('/')}/cli-auth?{query}"


def poll_status() -> dict[str, Any]:
    """Report and, on success, persist the pending login's result.

    Returns `{status: idle|pending|success|failed, error?}`. Success and
    failure are terminal: the loopback listener is torn down before returning.
    """
    with _lock:
        session = _session
        if session is None:
            return {"status": "idle"}
        if session.status == "pending" and session.expired():
            session.status = "failed"
            session.error = "Login timed out. Please try again."
        if session.status == "success":
            device_code = session.device_code
            _shutdown_locked()
        elif session.status == "failed":
            error = session.error or "Login failed."
            _shutdown_locked()
            return {"status": "failed", "error": error}
        else:
            return {"status": "pending"}
    if not device_code:
        return {"status": "failed", "error": "Login completed without a device code."}
    # Redeem outside the lock: this is a network call, and the loopback
    # listener is already torn down.
    token, failure = redeem_device_code(device_code)
    if not token:
        return {"status": "failed", "error": failure or "Could not complete device sign-in."}
    persist_session_token(token)
    return {"status": "success"}
