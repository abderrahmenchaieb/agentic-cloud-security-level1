"""
Train the cloud integrity autoencoder of the Collect agent on flaws.cloud.

This script reproduces the training procedure of models/collect_cloud_ae_final.pt
with the settings reported in Appendix A of the review:

  windows       30 CloudTrail events per caller identity (userIdentity.arn),
                non-overlapping, windows with fewer than 5 events dropped
  descriptors   13 (see SCORE_NAMES); log1p applied to LOG_FEATURES,
                then standardisation
  architecture  13-24-12-6-3 encoder, mirrored decoder, ReLU
  optimiser     Adam, learning rate 0.003, weight decay 1e-5
  training      full batch (all windows at every step), 600 epochs, MSE
  threshold     97th percentile of the training reconstruction error

The original run fixed no random seed, so this script reproduces an
equivalent model rather than the published weights bit for bit. It fixes
the seed to 42 so that its own runs are repeatable.

Data: download https://summitroute.com/downloads/flaws_cloudtrail_logs.tar
and extract it into ./flaws_data before running.

Usage:
  python training/train_cloud_autoencoder.py --data flaws_data --out models/
"""
import argparse
import glob
import gzip
import json
import os
from datetime import datetime

import joblib
import numpy as np
import torch
import torch.nn as nn

SCORE_NAMES = ["n_events", "n_services", "n_actions", "ratio_err", "ratio_recon",
               "ratio_write", "ratio_readonly", "gap_mean", "gap_std", "gap_max",
               "velocity", "n_ips", "n_useragents"]
IDX = {n: i for i, n in enumerate(SCORE_NAMES)}
LOG_FEATURES = ["gap_mean", "gap_std", "gap_max", "velocity", "n_events"]
WINDOW = 30
MIN_EVENTS = 5
RECON_PREFIXES = ("Describe", "List", "Get")


def load_events(directory):
    events = []
    for path in glob.glob(os.path.join(directory, "**", "*.json.gz"), recursive=True):
        try:
            with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as fh:
                events.extend(json.load(fh).get("Records", []))
        except (OSError, ValueError):
            continue
    return events


def event_time(ev):
    try:
        return datetime.strptime(ev.get("eventTime", ""), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def identity(ev):
    ui = ev.get("userIdentity", {}) or {}
    return (ui.get("arn") or ui.get("principalId") or ui.get("accessKeyId")
            or ui.get("type", "?"))


def window_scores(win):
    n = len(win)
    actions = [e.get("eventName", "") for e in win]
    services = [e.get("eventSource", "") for e in win]
    n_err = sum(1 for e in win if e.get("errorCode"))
    n_recon = sum(1 for a in actions if a.startswith(RECON_PREFIXES))
    n_write = sum(1 for a in actions if not a.startswith(RECON_PREFIXES))
    n_readonly = sum(1 for e in win if str(e.get("readOnly")).lower() == "true")
    times = [t for t in (event_time(e) for e in win) if t]
    if len(times) > 1:
        gaps = np.diff(sorted(t.timestamp() for t in times))
        gap_mean, gap_std, gap_max = gaps.mean(), gaps.std(), gaps.max()
        duration = (max(times) - min(times)).total_seconds()
    else:
        gap_mean = gap_std = gap_max = duration = 0.0
    velocity = n / duration if duration > 0 else float(n)
    n_ips = len({str(e.get("sourceIPAddress", "")) for e in win})
    n_agents = len({str(e.get("userAgent", "")) for e in win})
    return [float(n), float(len(set(services))), float(len(set(actions))),
            n_err / n, n_recon / n, n_write / n, n_readonly / n,
            gap_mean, gap_std, gap_max, velocity, float(n_ips), float(n_agents)]


def build_windows(events):
    by_identity = {}
    for ev in events:
        if event_time(ev):
            by_identity.setdefault(identity(ev), []).append(ev)
    rows = []
    for evs in by_identity.values():
        evs.sort(key=event_time)
        for start in range(0, max(1, len(evs) - WINDOW), WINDOW):
            win = evs[start:start + WINDOW]
            if len(win) >= MIN_EVENTS:
                rows.append(window_scores(win))
    return np.nan_to_num(np.array(rows, dtype=float), nan=0.0)


def apply_log(X):
    Xl = X.copy()
    for name in LOG_FEATURES:
        i = IDX[name]
        Xl[:, i] = np.log1p(np.abs(Xl[:, i]))
    return Xl


class AE(nn.Module):
    def __init__(self, d):
        super().__init__()
        self.enc = nn.Sequential(nn.Linear(d, 24), nn.ReLU(), nn.Linear(24, 12), nn.ReLU(),
                                 nn.Linear(12, 6), nn.ReLU(), nn.Linear(6, 3))
        self.dec = nn.Sequential(nn.Linear(3, 6), nn.ReLU(), nn.Linear(6, 12), nn.ReLU(),
                                 nn.Linear(12, 24), nn.ReLU(), nn.Linear(24, d))

    def forward(self, x):
        return self.dec(self.enc(x))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="flaws_data")
    ap.add_argument("--out", default="models")
    ap.add_argument("--epochs", type=int, default=600)
    ap.add_argument("--lr", type=float, default=0.003)
    ap.add_argument("--weight-decay", type=float, default=1e-5)
    ap.add_argument("--percentile", type=float, default=97.0)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    np.random.seed(args.seed)
    torch.manual_seed(args.seed)

    events = load_events(args.data)
    print(f"events: {len(events):,}")
    X = build_windows(events)
    print(f"windows: {X.shape}")

    Xlog = apply_log(X)
    mean, std = Xlog.mean(0), Xlog.std(0)
    std[std == 0] = 1.0
    Xt = torch.tensor((Xlog - mean) / std, dtype=torch.float32)

    model = AE(X.shape[1])
    opt = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    for epoch in range(args.epochs):
        opt.zero_grad()
        loss = ((model(Xt) - Xt) ** 2).mean()
        loss.backward()
        opt.step()
        if (epoch + 1) % 100 == 0:
            print(f"epoch {epoch + 1} | loss {loss.item():.4f}")

    model.eval()
    with torch.no_grad():
        err = ((model(Xt) - Xt) ** 2).mean(1).numpy()
    threshold = float(np.percentile(err, args.percentile))
    print(f"threshold (p{args.percentile:g}): {threshold:.4f}")

    os.makedirs(args.out, exist_ok=True)
    torch.save(model.state_dict(), os.path.join(args.out, "collect_cloud_ae_retrained.pt"))
    joblib.dump({"mean": mean, "std": std, "seuil": threshold, "score_names": SCORE_NAMES,
                 "log_features": LOG_FEATURES, "window_size": WINDOW},
                os.path.join(args.out, "collect_cloud_ae_retrained_config.pkl"))


if __name__ == "__main__":
    main()
