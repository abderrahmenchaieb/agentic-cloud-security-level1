# Agentic cloud security, Level 1: code and data for reproduction

This repository holds the Level-1 agents of the two-level agentic architecture
described in:

- *The Evolution of AI in Cloud Security* (review, under revision), Section 7
  and Appendix A.
- *An Agentic System for Cloud Security: Integrity-Aware Threat Detection,
  Dataset Selection and Experimental Evaluation* (companion paper, under review).

It contains the four Level-1 agents (Collect, Analysis, Anonymization,
Decision), the agentic layer and its request bus, the AWS CloudTrail adapter,
the trained models with their configurations, the experiment scripts and the
calibration grid of the Decision agent. The Level-2 investigation stage is not
included: it is the subject of a separate study. The operator web interface is
not included either.

Source comments and console messages are in French.

## Layout

| Path | Content |
|---|---|
| `agents/1_collect_agent` | Mapper, forensic rules F1 to F9, gap detection, window autoencoder, falsification generator |
| `agents/2_analysis_agent` | Sequence builder, Windows and cloud features, random-forest detector, ATT&CK retrieval and interpreter |
| `agents/3_anonymization_detection_agent` | Lookup stage, graph builder, E-GraphSAGE, Anomal-E |
| `agents/4_decision_agent` | Correlator, certainty evaluator (rules D1 to D6), Level-2 router, action generator, ATT&CK defence base |
| `agents/4_decision_agent/calibration` | Threshold calibration on the 45-scenario grid |
| `agentic_layer` | Agent wrappers and the synchronous in-memory request bus |
| `cloud_adapter` | CloudTrail to canonical schema, cloud sequence builder and features |
| `models` | Trained models and their configurations |
| `services` | Agent services and experiment scripts E0 to E5 |
| `training` | Training script for the cloud integrity autoencoder |
| `supplementary/decision_grid_45_scenarios.csv` | The 45 scenarios and the decision the doctrine expects for each |
| `docker`, `dashboard_realtime/bus` | Containerised deployment and the HTTP version of the bus |

## Data

The corpora are public and are not redistributed here.

| Corpus | Use | Source |
|---|---|---|
| COMISET (Lab and Real) | Windows integrity and threat detection | Zenodo, DOI 10.5281/zenodo.15375145 |
| Invictus AWS dataset | Cloud threat detection | GitHub, `invictus-ir/aws_dataset` |
| flaws.cloud CloudTrail logs | Cloud integrity autoencoder | `https://summitroute.com/downloads/flaws_cloudtrail_logs.tar` |
| CIC-Darknet2020 | Tor and VPN detection | `https://www.unb.ca/cic/datasets/darknet2020.html` |

Use the raw `Darknet.csv` file, which keeps the source and destination
addresses needed to build the flow graph.

## Environment

Inference and the experiments were run with Python 3.12 on CPU. The random
forests were trained with scikit-learn 1.6.1 and must be loaded with that
version: other versions raise `InconsistentVersionWarning` and can return
wrong predictions without an error.

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The latency measurements of the paper were taken on a laptop with a
12th Gen Intel Core i5-1235U (1.30 GHz) and 32 GB of RAM, without a GPU,
in a single process outside containers.

## Reproducing the results

Set the repository root once:

```
export REPO_ROOT="$(pwd)"
```

| Result | Command |
|---|---|
| Unit and integration tests | `bash run_all_tests.sh` |
| Decision thresholds, 45-scenario grid, stability ranges | `cd agents/4_decision_agent && python calibration/calibration_seuils_decision.py` |
| E0, repeated runs give identical counts | `python services/E0_reproductibilite.py --csv Darknet.csv` |
| E1, transport and conservation | `python services/E1_integrite_fonctionnelle.py` |
| E2, threat detection on Windows | `python services/E2_detection_menace.py --csv <COMISET csv>` |
| E3, integrity detection on injected falsifications | `python services/E3_robustesse_integrite.py --csv <COMISET csv>` |
| E4, correlation and decision | `python services/E4_correlation_decision.py` |
| E5, latency per stage | `python services/E5_performance.py --csv <COMISET csv> --n 20000` |
| Cloud integrity autoencoder | `python training/train_cloud_autoencoder.py --data flaws_data` |

E0 and E1 drive the agents as services. Start them first with
`docker/demarrer.sh`, or run the four `services/service_*.py` and
`dashboard_realtime/run_bus.py` by hand.

The Windows extraction and retraining steps are in
`services/extraire_classes_comparables.py`,
`services/reentrainer_detecteur_windows.py`,
`services/construire_fenetres_temporel.py` and
`services/entrainer_depuis_matrice.py`.

## What is and is not reproducible exactly

- The random forests, the Windows autoencoder, E-GraphSAGE, the isolation
  forest of Anomal-E and the data splits use seed 42. The Anomal-E encoder
  (Deep Graph Infomax) was trained without a fixed seed.
- The published cloud autoencoder was trained without a fixed seed.
  `training/train_cloud_autoencoder.py` uses the same data, architecture and
  settings with seed 42, so it reproduces an equivalent model rather than the
  published weights.
- The language-model interpreter and action generator were exercised only
  with a stand-in model. No reported figure depends on a language model.

## Licence

MIT, see `LICENSE`. The corpora keep their own licences.
