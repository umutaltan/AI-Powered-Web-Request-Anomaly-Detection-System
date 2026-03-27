import argparse, json, os, joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report
from features import extract_features

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out_dir", required=True)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    
    X_all, y_all = [], []
    X_normals = [] # Sadece IForest için
    
    print("[INFO] Veri seti yükleniyor...")
    with open(args.inp, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip(): continue
            try: rec = json.loads(line)
            except: continue
            
            lbl = rec.get("label", "normal").lower()
            target = 1 if lbl in ["anomalous", "1", "malicious"] else 0
            
            feats = extract_features(
                rec.get("method"), rec.get("path"), rec.get("ua"),
                rec.get("cookie"), rec.get("content")
            )
            
            X_all.append(feats)
            y_all.append(target)
            
            # Normal verileri ayır
            if target == 0:
                X_normals.append(feats)

    X_all = np.vstack(X_all)
    y_all = np.array(y_all)
    X_normals = np.vstack(X_normals)
    
    print(f"[INFO] Toplam: {len(X_all)} | Normal (Eğitim): {len(X_normals)}")
    
    # 1. IForest: Sadece Normallerle Eğit (Anomaly Detection Mantığı)
    print("[INFO] Isolation Forest (Sadece Normallerle) Eğitiliyor...")
    if_model = IsolationForest(n_estimators=100, contamination=0.01, n_jobs=-1, random_state=42)
    if_model.fit(X_normals)
    
    # Skorları Tüm Veri İçin Üret
    if_scores = if_model.decision_function(X_all).reshape(-1, 1)
    
    # 2. Random Forest: Stacking
    print("[INFO] Random Forest (Stacking) Eğitiliyor...")
    X_stacked = np.hstack((X_all, if_scores))
    
    rf_model = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42, class_weight="balanced")
    rf_model.fit(X_stacked, y_all)
    
    print("[INFO] Eğitim Performansı:")
    print(classification_report(y_all, rf_model.predict(X_stacked), target_names=["Normal", "Saldırı"]))
    
    joblib.dump(if_model, os.path.join(args.out_dir, "if_model.joblib"))
    joblib.dump(rf_model, os.path.join(args.out_dir, "rf_model.joblib"))
    print(f"[OK] Modeller kaydedildi: {args.out_dir}")

if __name__ == "__main__": main()