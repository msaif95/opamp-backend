#!/usr/bin/env python3
"""Prints fleet state, API latency and backend resource use for scale testing.

  scripts/scale-probe.py [api_base ...]     default: http://localhost:8080

Logs in as the dev local admin (LOCAL_ADMIN_PASSWORD, default "admin").
"""
import json, os, statistics, subprocess, sys, time, urllib.request

bases = sys.argv[1:] or ["http://localhost:8080"]


def call(base, method, path, body=None, token=None):
    req = urllib.request.Request(
        base + "/api/v1" + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": "Bearer " + token} if token else {})
    with urllib.request.urlopen(req, timeout=60) as r:
        raw = r.read()
        return json.loads(raw) if raw else None


token = call(bases[0], "POST", "/auth/login",
             {"username": "admin", "password": os.environ.get("LOCAL_ADMIN_PASSWORD", "admin")})["token"]
print("summary:", call(bases[0], "GET", "/summary", token=token))

uid = call(bases[0], "GET", "/agents?limit=1", token=token)["agents"][0]["instance_uid"]
endpoints = {
    "summary": "/summary",
    "agents page 1": "/agents?limit=50",
    "agents deep page": "/agents?limit=50&offset=15000",
    "agents filtered": "/agents?limit=50&attr=env=prod&attr=region=us-east-1",
    "agents unhealthy": "/agents?limit=50&connected=true&healthy=false",
    "agents by last_seen": "/agents?limit=50&sort=last_seen&order=desc",
    "agent detail": "/agents/" + uid,
    "facets": "/agents/facets",
    "configs": "/configs",
    "rollouts": "/rollouts",
}
print(f"{'endpoint':22} {'p50 ms':>8} {'p95 ms':>8} {'max ms':>8}")
for name, path in endpoints.items():
    times = []
    for i in range(20):
        t0 = time.perf_counter()
        call(bases[i % len(bases)], "GET", path, token=token)
        times.append((time.perf_counter() - t0) * 1000)
    times.sort()
    print(f"{name:22} {statistics.median(times):8.1f} {times[int(len(times) * 0.95) - 1]:8.1f} {times[-1]:8.1f}")

print("\nprocesses (cpu% is a lifetime average):")
out = subprocess.run(["ps", "-axo", "pid,pcpu,rss,command"], capture_output=True, text=True).stdout
for line in out.splitlines():
    if "bin/opamp-backend" in line or "bin/agentsim" in line:
        pid, cpu, rss, cmd = line.split(None, 3)
        print(f"  {cmd.split()[0]:20} pid {pid:>6} cpu {cpu:>5}% rss {int(rss) / 1024:7.0f} MB")
