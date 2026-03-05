import json
import math
from itertools import cycle

SUPPORTED_SCHEMA_VERSION = 20221207

RCODES = {
    "NOERROR",
    "FORMERR",
    "SERVFAIL",
    "NXDOMAIN",
    "NOTIMP",
    "REFUSED",
    "YXDOMAIN",
    "YXRRSET",
    "NXRRSET",
    "NOTAUTH",
    "NOTZONE",
    "BADVERS",
    "BADKEY",
    "BADTIME",
    "BADMODE",
    "BADNAME",
    "BADALG",
    "BADTRUNC",
    "BADCOOKIE",
    "other",
}

RCODE_MARKERS = {
    "FORMERR": "f",
    "SERVFAIL": "s",
    "NXDOMAIN": "n",
    "NOTIMP": "i",
    "REFUSED": "r",
    "other": "?",
}

RCODE_COLORS = {
    "NOERROR":   "tab:green",
    "FORMERR":   "tab:brown",
    "SERVFAIL":  "tab:red",
    "NXDOMAIN":  "tab:blue",
    "NOTIMP":    "tab:pink",
    "REFUSED":   "tab:orange",
    "YXDOMAIN":  "tab:purple",
    "YXRRSET":   "tab:olive",
    "NXRRSET":   "tab:cyan",
    "NOTAUTH":   "#f0944d",
    "NOTZONE":   "#840000",
    "BADVERS":   "#ac7e04",
    "BADKEY":    "#5d1451",
    "BADTIME":   "#fdb0c0",
    "BADMODE":   "#fd3c06",
    "BADNAME":   "#536267",
    "BADALG":    "#a03623",
    "BADTRUNC":  "#b7e1a1",
    "BADCOOKIE": "#0a888a",
    "other":     "#000000",
}

COLOR_ACTIVE = cycle(["royalblue", "cornflowerblue", "darkblue", "lightsteelblue"])
COLOR_CONN_HS = cycle(["forestgreen", "limegreen", "darkgreen", "lightgreen"])
COLOR_QUIC_0RTT = cycle(
    ["darkolivegreen", "darkseagreen", "darkslategray", "greenyellow"]
)
COLOR_QUIC_0RTT_SENT = cycle(["crimson", "brown", "firebrick", "indianred"])
COLOR_QUIC_0RTT_ANSWERED = cycle(["khaki", "moccasin", "peru", "wheat"])
COLOR_TLS_RESUMED = cycle(["orange", "moccasin", "darkorange", "antiquewhite"])
COLOR_FAILED_HS = cycle(["gray", "silver", "black", "gainsboro"])

sinames = ["", " k", " M", " G", " T"]

def siname(n):
    try:
        n = float(n)
    except ValueError:
        return n

    siidx = max(
        0,
        min(len(sinames) - 1, int(math.floor(0 if n == 0 else math.log10(abs(n)) / 3))),
    )
    return f"{(n / 10 ** (3 * siidx)):.0f}{sinames[siidx]}"

def load_json_lines_file(json_file):
    header = None
    stats_sum = None
    stats_periodic = []

    if hasattr(json_file, 'read'):
        path = json_file.name
    else:
        path = json_file

    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"JSON parse error in {path} line {lineno}: {exc}") from exc

            t = obj.get("type")
            if t == "header":
                header = obj
            elif t == "stats_sum":
                stats_sum = obj
            elif t in ("stats_periodic", "stats_interval"):
                stats_periodic.append(obj)

    if header is None:
        raise NotImplementedError(
            "Missing header line. Use newer shotgun or re-run the tests."
        )
    if header.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        raise NotImplementedError(
            f"Unsupported schema_version {header.get('schema_version')}. "
            "Use older tooling or re-run the tests with newer shotgun."
        )
    return header, stats_sum, stats_periodic
