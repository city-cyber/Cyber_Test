import json
import os
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import requests

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = BASE_DIR / "results"

VULNERS_FALLBACK_FILE = DATA_DIR / "sample_vulners.json"
SURICATA_FILE = DATA_DIR / "sample_suricata_eve.jsonl"

CVSS_THRESHOLD = 8.0
DNS_SPIKE_THRESHOLD = 6


def fetch_vulners_data() -> tuple[list[dict], str]:
    """Try Vulners API first, fallback to local sample JSON."""
    api_key = os.getenv("VULNERS_API_KEY", "").strip()

    if api_key:
        url = "https://vulners.com/api/v3/search/lucene/"
        params = {
            "query": "type:cve",
            "size": 20,
            "apiKey": api_key,
        }
        try:
            response = requests.get(url, params=params, timeout=15)
            response.raise_for_status()
            payload = response.json()
            docs = payload.get("data", {}).get("search", [])

            vulns = []
            for doc in docs:
                cvss = doc.get("cvss", {}) or {}
                score = cvss.get("score")
                if score is None:
                    score = doc.get("cvss3", {}).get("cvssV3", {}).get("baseScore")
                vulns.append(
                    {
                        "id": doc.get("id", "unknown"),
                        "title": doc.get("title", ""),
                        "cvss": float(score) if score is not None else 0.0,
                        "published": doc.get("published") or doc.get("lastseen"),
                        "references": [doc.get("href")] if doc.get("href") else [],
                    }
                )
            if vulns:
                return vulns, "vulners_api"
        except Exception as exc:
            print(f"[WARN] Vulners API unavailable, fallback to local data: {exc}")

    local_data = json.loads(VULNERS_FALLBACK_FILE.read_text(encoding="utf-8"))
    return local_data, "local_vulners_sample"


def load_suricata_events() -> pd.DataFrame:
    rows = []
    with SURICATA_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            evt = json.loads(line)
            rows.append(
                {
                    "timestamp": evt.get("timestamp"),
                    "event_type": evt.get("event_type"),
                    "src_ip": evt.get("src_ip"),
                    "dest_ip": evt.get("dest_ip"),
                    "severity": (evt.get("alert") or {}).get("severity"),
                    "signature": (evt.get("alert") or {}).get("signature"),
                    "dns_rrname": (evt.get("dns") or {}).get("rrname"),
                }
            )

    df = pd.DataFrame(rows)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def analyze(vulns: list[dict], suricata_df: pd.DataFrame) -> dict:
    vulns_df = pd.DataFrame(vulns)
    if "cvss" not in vulns_df.columns:
        vulns_df["cvss"] = 0.0

    vulns_df["cvss"] = pd.to_numeric(vulns_df["cvss"], errors="coerce").fillna(0.0)
    high_cvss = vulns_df[vulns_df["cvss"] >= CVSS_THRESHOLD].copy()

    alerts_df = suricata_df[suricata_df["event_type"] == "alert"].copy()
    dns_df = suricata_df[suricata_df["event_type"] == "dns"].copy()

    alert_counts = alerts_df.groupby("src_ip").size().rename("alert_count")
    high_severity_counts = (
        alerts_df[alerts_df["severity"].fillna(99) <= 2]
        .groupby("src_ip")
        .size()
        .rename("high_severity_alert_count")
    )
    dns_counts = dns_df.groupby("src_ip").size().rename("dns_query_count")

    suspicious = pd.concat([alert_counts, high_severity_counts, dns_counts], axis=1).fillna(0).reset_index()
    suspicious[["alert_count", "high_severity_alert_count", "dns_query_count"]] = suspicious[
        ["alert_count", "high_severity_alert_count", "dns_query_count"]
    ].astype(int)

    suspicious["risk_score"] = (
        suspicious["high_severity_alert_count"] * 5
        + suspicious["alert_count"] * 2
        + (suspicious["dns_query_count"] >= DNS_SPIKE_THRESHOLD).astype(int) * 3
    )
    suspicious = suspicious.sort_values("risk_score", ascending=False)

    threats = suspicious[(suspicious["risk_score"] >= 5)].copy()

    return {
        "vulns_df": vulns_df,
        "high_cvss": high_cvss,
        "alerts_df": alerts_df,
        "suspicious": suspicious,
        "threats": threats,
        "stats": {
            "total_vulns": int(len(vulns_df)),
            "high_cvss_count": int(len(high_cvss)),
            "suricata_events": int(len(suricata_df)),
            "alert_events": int(len(alerts_df)),
            "dns_events": int(len(dns_df)),
            "threat_ips": int(len(threats)),
        },
    }


def simulate_response(threats_df: pd.DataFrame) -> list[dict]:
    actions = []
    if threats_df.empty:
        print("[INFO] Threats not detected.")
        return actions

    telegram_chat = os.getenv("TELEGRAM_CHAT_ID", "")
    alert_email = os.getenv("ALERT_EMAIL", "")

    for _, row in threats_df.iterrows():
        src_ip = row["src_ip"]
        score = int(row["risk_score"])

        block_msg = f"[ACTION] SIMULATED BLOCK: {src_ip} (risk_score={score})"
        notify_msg = f"[ALERT] Threat detected from {src_ip}. Risk score={score}."

        print(block_msg)
        print(notify_msg)

        if telegram_chat:
            print(f"[NOTIFY] Telegram message to chat {telegram_chat}: {notify_msg}")
        if alert_email:
            print(f"[NOTIFY] Email to {alert_email}: {notify_msg}")

        actions.append(
            {
                "src_ip": src_ip,
                "risk_score": score,
                "simulated_block": True,
                "notification": notify_msg,
            }
        )

    return actions


def save_outputs(analysis_result: dict, actions: list[dict], source_label: str) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    analysis_result["high_cvss"].to_csv(RESULTS_DIR / "high_cvss_vulns.csv", index=False)
    analysis_result["suspicious"].to_csv(RESULTS_DIR / "suspicious_ips.csv", index=False)
    analysis_result["alerts_df"].to_csv(RESULTS_DIR / "alerts.csv", index=False)

    report = {
        "data_sources": {
            "vulnerabilities": source_label,
            "suricata": str(SURICATA_FILE.name),
        },
        "thresholds": {
            "cvss": CVSS_THRESHOLD,
            "dns_spike": DNS_SPIKE_THRESHOLD,
        },
        "stats": analysis_result["stats"],
        "response_actions": actions,
    }
    (RESULTS_DIR / "analysis_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    plot_top_ips(analysis_result["suspicious"])


def plot_top_ips(suspicious_df: pd.DataFrame) -> None:
    if suspicious_df.empty:
        return

    top = suspicious_df.head(5)

    plt.figure(figsize=(8, 4))
    plt.bar(top["src_ip"], top["risk_score"])
    plt.title("Top suspicious IPs by risk score")
    plt.xlabel("Source IP")
    plt.ylabel("Risk score")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "top_suspicious_ips.png", dpi=140)
    plt.close()


def main() -> None:
    vulns, source_label = fetch_vulners_data()
    suricata_df = load_suricata_events()

    result = analyze(vulns, suricata_df)
    actions = simulate_response(result["threats"])
    save_outputs(result, actions, source_label)

    print("\n=== Summary ===")
    for key, value in result["stats"].items():
        print(f"{key}: {value}")
    print(f"\nOutputs saved to: {RESULTS_DIR}")


if __name__ == "__main__":
    main()
