#!python3
import collections
import io
import json
import re
import time
import traceback
import typing
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PARSER_RE = re.compile(
    r"""
^
(?:
    (?:VERSION: \ .+/(?P<version>.+)) |
    (?:
        UPTIME:
        \ (?:(?P<uptime_days>\d+)\ day(?:s?)\ )?
        (?P<uptime_hours>\d+):
        (?P<uptime_minutes>\d+):
        (?P<uptime_seconds>\d+)
    ) |
    (?:
        BPS_IN: \ (?P<bps_in>\d+),
        \ BPS_OUT: \ (?P<bps_out>\d+),
        \ SSL_BPS_IN: \ (?P<ssl_bps_in>\d+),
        \ SSL_BPS_OUT: \ (?P<ssl_bps_out>\d+)
    ) |
    (?:
        MAXCONN: \ (?P<maxconn>\d+),
        \ MAXSSL_CONN: \ (?P<maxssl_conn>\d+),
        \ PLAINCONN: \ (?P<plainconn>\d+),
        \ AVAILCONN: \ (?P<availconn>\d+),
        \ IDLECONN: \ (?P<idleconn>\d+),
        \ SSLCONN: \ (?P<sslconn>\d+),
        \ AVAILSSL: \ (?P<availssl>\d+)
    ) |
    (?:
        REQ_RATE \ \[(?P<req_rate>[^\]]*)\]:
        \ REQ_PROCESSING: \ (?P<req_processing>\d+),
        \ REQ_PER_SEC: \ (?P<req_per_sec>\d+(?:\.\d+)?),
        \ TOT_REQS: \ (?P<tot_reqs>\d+),
        \ PUB_CACHE_HITS_PER_SEC: \ (?P<pub_cache_hits_per_sec>\d+(?:\.\d+)?),
        \ TOTAL_PUB_CACHE_HITS: \ (?P<total_pub_cache_hits>\d+),
        \ PRIVATE_CACHE_HITS_PER_SEC: \ (?P<private_cache_hits_per_sec>\d+(?:\.\d+)?),
        \ TOTAL_PRIVATE_CACHE_HITS: \ (?P<total_private_cache_hits>\d+),
        \ STATIC_HITS_PER_SEC: \ (?P<static_hits_per_sec>\d+(?:\.\d+)?),
        \ TOTAL_STATIC_HITS: \ (?P<total_static_hits>\d+)
    ) |
    (?:
        EXTAPP
        \ \[(?P<extapp>[^\]]*)\]
        \ \[(?P<extapp_mid>[^\]]*)\]
        \ \[(?P<extapp_name>[^\]]*)\]:
        \ CMAXCONN: \ (?P<cmaxconn>\d+),
        \ EMAXCONN: \ (?P<emaxconn>\d+),
        \ POOL_SIZE: \ (?P<pool_size>\d+),
        \ INUSE_CONN: \ (?P<inuse_conn>\d+),
        \ IDLE_CONN: \ (?P<idle_conn>\d+),
        \ WAITQUE_DEPTH: \ (?P<waitque_depth>\d+),
        \ REQ_PER_SEC: \ (?P<req_per_sec2>\d+(?:\.\d+)?),
        \ TOT_REQS: \ (?P<tot_reqs2>\d+)
    ) |
    (?P<blocked_ip>BLOCKED_IP:) |
    (?P<eof>EOF)
)
$
""",
    re.X,
)


class RequestRate(typing.NamedTuple):
    name: str
    req_processing: int
    req_per_sec: float
    tot_reqs: int
    pub_cache_hits_per_sec: float
    total_pub_cache_hits: int
    private_cache_hits_per_sec: float
    total_private_cache_hits: int
    static_hits_per_sec: float
    total_static_hits: int


class ExtApp(typing.NamedTuple):
    app: str
    mid: str
    name: str
    cmaxconn: int
    emaxconn: int
    pool_size: int
    inuse_conn: int
    idle_conn: int
    waitque_depth: int
    req_per_sec: float
    tot_reqs: int


class Report(typing.NamedTuple):
    version: str
    uptime: int
    bps_in: int
    bps_out: int
    ssl_bps_in: int
    ssl_bps_out: int
    maxconn: int
    maxssl_conn: int
    plainconn: int
    availconn: int
    idleconn: int
    sslconn: int
    availssl: int
    req_rate: typing.List[RequestRate]
    extapp: typing.List[ExtApp]

    invalid_lines: int


def parse_file(inf: io.StringIO) -> Report:
    data = {"req_rate": [], "extapp": []}
    invalid_lines = 0
    for line in inf:
        if not line.strip():
            # Empty lines aren't invalid.
            continue
        md = PARSER_RE.match(line)
        if md is None:
            invalid_lines += 1
            continue
        elif md["version"]:
            data["version"] = md["version"]
        elif md["uptime_hours"] is not None:
            data["uptime"] = (
                int(md["uptime_seconds"])
                + (int(md["uptime_minutes"]) * 60)
                + (int(md["uptime_hours"]) * 3600)
                + (int(md["uptime_days"] or "0") * 86400)
            )
        elif md["bps_in"] is not None:
            data["bps_in"] = int(md["bps_in"])
            data["bps_out"] = int(md["bps_out"])
            data["ssl_bps_in"] = int(md["ssl_bps_in"])
            data["ssl_bps_out"] = int(md["ssl_bps_out"])
        elif md["maxconn"] is not None:
            data["maxconn"] = int(md["maxconn"])
            data["maxssl_conn"] = int(md["maxssl_conn"])
            data["plainconn"] = int(md["plainconn"])
            data["availconn"] = int(md["availconn"])
            data["idleconn"] = int(md["idleconn"])
            data["sslconn"] = int(md["sslconn"])
            data["availssl"] = int(md["availssl"])
        elif md["req_rate"] is not None:
            rate = RequestRate(
                name=md["req_rate"],
                req_processing=int(md["req_processing"]),
                req_per_sec=float(md["req_per_sec"]),
                tot_reqs=int(md["tot_reqs"]),
                pub_cache_hits_per_sec=float(md["pub_cache_hits_per_sec"]),
                total_pub_cache_hits=int(md["total_pub_cache_hits"]),
                private_cache_hits_per_sec=float(md["private_cache_hits_per_sec"]),
                total_private_cache_hits=int(md["total_private_cache_hits"]),
                static_hits_per_sec=float(md["static_hits_per_sec"]),
                total_static_hits=int(md["total_static_hits"]),
            )
            data["req_rate"].append(rate)
        elif md["extapp"] is not None:
            app = ExtApp(
                app=md["extapp"],
                mid=md["extapp_mid"],
                name=md["extapp_name"],
                cmaxconn=int(md["cmaxconn"]),
                emaxconn=int(md["emaxconn"]),
                pool_size=int(md["pool_size"]),
                inuse_conn=int(md["inuse_conn"]),
                idle_conn=int(md["idle_conn"]),
                waitque_depth=int(md["waitque_depth"]),
                req_per_sec=float(md["req_per_sec2"]),
                tot_reqs=int(md["tot_reqs2"]),
            )
            data["extapp"].append(app)
        elif md["blocked_ip"] is not None:
            # Ignored
            pass
        elif md["eof"] is not None:
            # Ignored
            pass
        else:
            invalid_lines += 1
    data["invalid_lines"] = invalid_lines
    return Report(**data)


def test_parse_file():
    r = parse_file(open("holy.rtreport"))
    assert r.version == "6.1.2"
    assert r.uptime == 323_247
    assert r.bps_in == 293
    assert r.bps_out == 573
    assert r.ssl_bps_in == 0
    assert r.ssl_bps_out == 0
    assert r.maxconn == 10_000
    assert r.availconn == 8881
    assert r.req_rate[0].name == ""
    assert r.req_rate[0].tot_reqs == 181475371
    assert r.req_rate[1].name == "APVH_farmrpg.com:0"
    assert r.req_rate[1].req_per_sec == 536.2
    assert r.extapp[0].app == "CGI"
    assert r.extapp[0].name == "lscgid"
    assert r.extapp[0].emaxconn == 200
    assert r.extapp[0].tot_reqs == 36
    assert r.extapp[1].req_per_sec == 253.2
    assert r.invalid_lines == 0


class Metric(typing.NamedTuple):
    type: str
    name: str
    labels: typing.Dict[str, str]
    value: typing.Union[int, float]
    unit: typing.Optional[str] = None
    help: typing.Optional[str] = None


def generate_metrics(reports: typing.List[Report]) -> typing.Iterable[Metric]:
    for i, rep in enumerate(reports):
        yield Metric(
            type="info",
            name="info",
            labels={"report": i + 1, "version": rep.version},
            value=1,
        )
        # UPTIME line.
        l = {"report": i + 1}
        yield Metric(
            type="gauge",
            name="uptime_seconds",
            labels=l,
            value=rep.uptime,
            unit="seconds",
        )
        # BPS_IN line.
        yield Metric(
            type="gauge",
            name="bps_in",
            labels=l,
            value=rep.bps_in,
        )
        yield Metric(
            type="gauge",
            name="bps_out",
            labels=l,
            value=rep.bps_out,
        )
        yield Metric(
            type="gauge",
            name="ssl_bps_in",
            labels=l,
            value=rep.ssl_bps_in,
        )
        yield Metric(
            type="gauge",
            name="ssl_bps_out",
            labels=l,
            value=rep.ssl_bps_out,
        )
        # MAXCONN line.
        yield Metric(
            type="gauge",
            name="maxconn",
            labels=l,
            value=rep.maxconn,
        )
        yield Metric(
            type="gauge",
            name="maxssl_conn",
            labels=l,
            value=rep.maxssl_conn,
        )
        yield Metric(
            type="gauge",
            name="plainconn",
            labels=l,
            value=rep.plainconn,
        )
        yield Metric(
            type="gauge",
            name="availconn",
            labels=l,
            value=rep.availconn,
        )
        yield Metric(
            type="gauge",
            name="idleconn",
            labels=l,
            value=rep.idleconn,
        )
        yield Metric(
            type="gauge",
            name="sslconn",
            labels=l,
            value=rep.sslconn,
        )
        yield Metric(
            type="gauge",
            name="availssl",
            labels=l,
            value=rep.availssl,
        )
        # REQ_RATE lines.
        for rate in rep.req_rate:
            if rate.name == "":
                # This appears to just be the sums and we can do those ourselves.
                continue
            l = {"report": i + 1, "req_rate": rate.name}
            yield Metric(
                type="gauge",
                name="req_rate_req_processing",
                labels=l,
                value=rate.req_processing,
            )
            yield Metric(
                type="gauge",
                name="req_rate_req_per_sec",
                labels=l,
                value=rate.req_per_sec,
            )
            yield Metric(
                type="counter",
                name="req_rate_tot_reqs",
                labels=l,
                value=rate.tot_reqs,
            )
            yield Metric(
                type="gauge",
                name="req_rate_pub_cache_hits_per_sec",
                labels=l,
                value=rate.pub_cache_hits_per_sec,
            )
            yield Metric(
                type="counter",
                name="req_rate_total_pub_cache_hits",
                labels=l,
                value=rate.total_pub_cache_hits,
            )
            yield Metric(
                type="gauge",
                name="req_rate_private_cache_hits_per_sec",
                labels=l,
                value=rate.private_cache_hits_per_sec,
            )
            yield Metric(
                type="counter",
                name="req_rate_total_private_cache_hits",
                labels=l,
                value=rate.total_private_cache_hits,
            )
            yield Metric(
                type="gauge",
                name="req_rate_static_hits_per_sec",
                labels=l,
                value=rate.static_hits_per_sec,
            )
            yield Metric(
                type="counter",
                name="req_rate_total_static_hits",
                labels=l,
                value=rate.total_static_hits,
            )
        # EXTAPP lines.
        for app in rep.extapp:
            l = {
                "report": i + 1,
                "extapp": app.app,
                "extapp_mid": app.mid,
                "extapp_name": app.name,
            }
            yield Metric(
                type="gauge",
                name="extapp_cmaxconn",
                labels=l,
                value=app.cmaxconn,
            )
            yield Metric(
                type="gauge",
                name="extapp_emaxconn",
                labels=l,
                value=app.emaxconn,
            )
            yield Metric(
                type="gauge",
                name="extapp_pool_size",
                labels=l,
                value=app.pool_size,
            )
            yield Metric(
                type="gauge",
                name="extapp_inuse_conn",
                labels=l,
                value=app.inuse_conn,
            )
            yield Metric(
                type="gauge",
                name="extapp_idle_conn",
                labels=l,
                value=app.idle_conn,
            )
            yield Metric(
                type="gauge",
                name="extapp_waitque_depth",
                labels=l,
                value=app.waitque_depth,
            )
            yield Metric(
                type="gauge",
                name="extapp_req_per_sec",
                labels=l,
                value=app.req_per_sec,
            )
            yield Metric(
                type="counter",
                name="extapp_tot_reqs",
                labels=l,
                value=app.tot_reqs,
            )


def _format_metric(
    f: io.StringIO,
    metrics: typing.List[Metric],
):
    m = metrics[0]
    f.write(f"# TYPE litespeed_{m.name} {m.type}\n")
    if m.unit is not None:
        f.write(f"# UNIT litespeed_{m.name} {m.unit}\n")
    if m.help is not None:
        f.write(f"# HELP litespeed_{m.name} {m.help}\n")
    for metric in metrics:
        assert metric.name == m.name
        f.write(f"litespeed_{metric.name}")
        if metric.labels:
            f.write("{")
            f.write(
                ",".join(
                    f"{label_key}={json.dumps(str(label_value))}"
                    for label_key, label_value in metric.labels.items()
                )
            )
            f.write("}")
        f.write(f" {metric.value}\n")


def format_metrics(metrics: typing.List[Metric]) -> str:
    f = io.StringIO()
    # Group the metrics by name.
    grouped_metrics = collections.defaultdict(list)
    for metric in metrics:
        grouped_metrics[metric.name].append(metric)

    for group in grouped_metrics.values():
        _format_metric(f, group)
    f.write("# EOF\n")
    return f.getvalue()


def test_generate_metrics():
    r = parse_file(open("holy.rtreport"))
    m = format_metrics(generate_metrics([r])).splitlines()
    assert m[0] == "# TYPE litespeed_info info"
    assert m[1] == 'litespeed_info{report="1",version="6.1.2"} 1'
    assert m[4] == 'litespeed_uptime{report="1"} 323247'
    assert (
        m[42]
        == 'litespeed_req_rate_static_hits_per_sec{report="1",req_rate="APVH_farmrpg.com:0"} 29.4'
    )
    assert m[43] == "# TYPE litespeed_req_rate_total_static_hits counter"


def find_reports() -> typing.Iterable[Report]:
    threshold = time.time() - 60
    for path in Path("/tmp/lshttpd").glob(".rtreport*"):
        if path.stat().st_mtime <= threshold:
            # Stale file that isn't being updated.
            continue
        with path.open() as f:
            yield parse_file(f)


class MetricsServer(BaseHTTPRequestHandler):
    def do_GET(self):
        # Try to generate metrics.
        try:
            reports = find_reports()
            metrics = generate_metrics(reports)
            output = format_metrics(metrics)
        except Exception:
            err = traceback.format_exc()
            print(err)
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(err.encode())
        else:
            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            )
            self.end_headers()
            self.wfile.write(output.encode())


def main():
    server = HTTPServer(("localhost", 9000), MetricsServer)
    print("Listening http://localhost:9000/")
    server.serve_forever()


if __name__ == "__main__":
    main()
