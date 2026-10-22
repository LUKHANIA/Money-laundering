# Anti - money laundering monitoring structure and circular flow detection 

import networkx as nx
import numpy as np
import pandas as pd

rng = np.random.default_rng(17)
accts = [f"ACC{i:04d}" for i in range(300)]
n = 6000
tx = pd.DataFrame({
    "ts": pd.Timestamp("2026-09-01") + pd.to_timedelta(rng.integers(0, 30 * 24 * 60, n), unit="m"),
    "src": rng.choice(accts, n), "dst": rng.choice(accts, n),
     "amount": rng.lognormal(7.5, 1.1, n).round(2),
    "channel": rng.choice(["eft", "cash_deposit", "card", "cash_withdrawal"], n, p=[0.4, 0.15, 0.35, 0.10]),
})

tx = tx[tx.src  != tx.dst]

#Inject two known laundering patterns so we can measure detection
inject = []
for acct, day in [("ACC0007", 5), ("ACC0042", 18)]: #cash limit under R50,000
    for k in range(5):
        inject.append({"ts": pd.Timestamp("2026-09-01") + pd.Timedelta(days=day, hours=9 + 6 * k),
                       "src": acct, "dst": "BANK", "amount": round(rng.uniform(44_000, 49_900), 2),
                       "channel": "cash_deposit"})

for rnd in range(3):  #round-tripping ring ACC0100 -> 0101 -> 0102 -> 0102 -> 0100
    for a, b in [("ACC0100", "ACC0101"), ("ACC0101", "ACC0102"), ("ACC0102", "ACC0100")]:
        inject.append({"ts": pd.Timestamp("2026-09-10") + pd.Timedelta(days=2 * rnd, hours=rng.integers(8, 18)),
                       "src": a, "dst": b, "amount": 85_000.0 - 500 * rnd, "channel": "eft"})
        tx = pd.concat([tx, pd.DataFrame(inject)], ignore_index=True).sort_values("ts")
        print(f"Transactions: {len(tx):,} across {tx.src.nunique()} accounts")

#Rule 1: 3 or more cash deposits of R40,000-R49,999,99 inside a rolling 3-day window 
cash = tx[(tx.channel == "cash_deposit") & tx.amount.between(40_000, 49_999.99)].set_index("ts").sort_index()
deposits_3d = cash.groupby("src")["amount"].rolling("3D").count()
structuring = set(deposits_3d[deposits_3d >=3].index.get_level_values("src"))

#Rule @: circular flow - builds graph of large EFT transfers and look short cycles
big = tx[(tx.channel == "eft") & (tx.amount >= 20_000)]
G = nx.DiGraph()
for r in big.itertuples():
    G.add_edge(r.src, r.dst)
cycles = [c for c in nx.simple_cycles(G, length_bound=4)]
circular = {a for c in cycles for a in c}

flagged = {"structuring": structuring, "circular_flow": circular}
truth = {"ACC0007", "ACC0024", "ACC0100", "ACC0101", "ACC0102"}
for rule, accs in flagged.items():
    print(f"{rule:<14} flagged {sorted(accs)}")
all_flagged = structuring | circular
print(f"\nPrecision {len(all_flagged & truth) / len(all_flagged):.0%}   recall {len(all_flagged & truth) / len(truth):.0%}")

#Combine into a simple risk score for compliance queue
score = pd.Series(0, index=sorted(all_flagged))
score[list(structuring)] += 60
score[list(circular)] += 50
print("\nInvestigation queue (highest score first):")
print(score.sort_values(ascending=False).to_string())