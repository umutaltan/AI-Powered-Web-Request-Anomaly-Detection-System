import argparse, json, os, joblib
import numpy as np
from urllib.parse import urlparse
from features import extract_features

SAFE_EXTENSIONS = (".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".woff", ".ttf")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--models", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    try:
        if_model = joblib.load(os.path.join(args.models, "if_model.joblib"))
        rf_model = joblib.load(os.path.join(args.models, "rf_model.joblib"))
    except:
        print("[HATA] Modeller yok.")
        return

    print("ts,method,path,risk,verdict")
    with open(args.inp, "r", encoding="utf-8") as fin, open(args.out, "w", encoding="utf-8") as fout:
        fout.write("ts,method,path,status,risk,verdict,label\n")
        
        batch_feats, batch_recs = [], []
        
        for line in fin:
            if not line.strip(): continue
            rec = json.loads(line)
            feats = extract_features(
                rec.get("method"), rec.get("path"), rec.get("ua"),
                rec.get("cookie"), rec.get("content")
            )
            batch_feats.append(feats)
            batch_recs.append(rec)
            
            if len(batch_feats) >= 5000:
                process_batch(batch_feats, batch_recs, if_model, rf_model, fout)
                batch_feats, batch_recs = [], []

        if batch_feats:
            process_batch(batch_feats, batch_recs, if_model, rf_model, fout)
    print(f"[OK] {args.out} hazır.")

def process_batch(feats, recs, if_model, rf_model, f_handle):
    X = np.vstack(feats)
    if_scores = if_model.decision_function(X).reshape(-1, 1)
    X_stacked = np.hstack((X, if_scores))
    probs = rf_model.predict_proba(X_stacked)[:, 1]
    
    for i, rec in enumerate(recs):
        risk = int(probs[i] * 100)
        
        # Whitelist
        attack_signals = sum(feats[i][3:8]) # Indexler features.py'ye göre
        try: path_clean = urlparse(rec.get("path", "")).path.lower()
        except: path_clean = ""
        
        if attack_signals == 0 and path_clean.endswith(SAFE_EXTENSIONS):
            risk = 0
        
        # EŞİK DEĞERİ: 50
        verdict = "malicious" if risk >= 50 else "benign"
        
        clean_path = str(rec.get('path','')).replace(",", " ")
        f_handle.write(f"{rec.get('ts','')},{rec.get('method')},{clean_path},{rec.get('status')},{risk},{verdict},{rec.get('label')}\n")

if __name__ == "__main__": main()