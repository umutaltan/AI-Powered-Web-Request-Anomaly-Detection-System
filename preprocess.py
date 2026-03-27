# preprocess.py
import argparse, os, json
import pandas as pd

NEEDED = ["Method", "User-Agent", "cookie", "content", "lenght", "classification", "URL"]

def load_csv_robust(path):
    last_err = None
    for enc in ("utf-8-sig", "utf-8", "latin1"):
        try: return pd.read_csv(path, encoding=enc, engine="python")
        except Exception as e: last_err = e
    raise RuntimeError(f"CSV error: {last_err}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", dest="out", required=True)
    args = ap.parse_args()

    df = load_csv_robust(args.inp)
    df.columns = [str(c).strip() for c in df.columns]
    
    # Temizlik
    if df.columns[0] in ("", "Unnamed: 0", "ï»¿"): df = df.drop(columns=[df.columns[0]])
    df = df.drop(columns=[c for c in df.columns if str(c).startswith("Unnamed")])
    
    missing = [c for c in NEEDED if c not in df.columns]
    if missing: raise SystemExit(f"Missing columns: {missing}")

    df = df[NEEDED].copy().fillna("")
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    
    with open(args.out, "w", encoding="utf-8") as f:
        for _, row in df.iterrows():
            try: cls = int(row["classification"])
            except: cls = 0
            label = "anomalous" if cls == 1 else "normal"
            
            try: length = int(row["lenght"])
            except: length = 0

            rec = {
                "ts": "", "client": "0.0.0.0", "status": 0,
                "method": str(row["Method"]),
                "path": str(row["URL"]),
                "ua": str(row["User-Agent"]),
                "cookie": str(row["cookie"]),
                "content": str(row["content"]),
                "bytes": length,
                "label": label
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"[OK] Converted to {args.out}")

if __name__ == "__main__": main()