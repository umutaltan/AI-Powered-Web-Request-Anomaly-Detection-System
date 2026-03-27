import argparse
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="score_stacking.py çıktısı")
    args = ap.parse_args()
    
    print(f"[INFO] Analiz ediliyor: {args.csv}")
    try:
        df = pd.read_csv(args.csv)
    except Exception as e:
        print(f"[HATA] CSV okunamadı: {e}")
        return

    # Etiketleri sayıya çevir
    # 1: Saldırı, 0: Normal
    y_true = df['label'].apply(lambda x: 1 if str(x).lower() in ['anomalous', '1', 'malicious'] else 0)
    
    # Tahminleri sayıya çevir
    # 'malicious' -> 1, diğerleri -> 0
    y_pred = df['verdict'].apply(lambda x: 1 if str(x) == 'malicious' else 0)
    
    print("\n" + "="*50)
    print("📊 PERFORMANS RAPORU")
    print("="*50)
    print(classification_report(y_true, y_pred, target_names=["Normal", "Saldırı"], digits=4))
    
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    print("-" * 50)
    print(f"✅ TP (Yakalanan Saldırı): {tp}")
    print(f"❌ FN (Kaçan Saldırı)    : {fn}")
    print(f"✅ TN (Doğru Normal)     : {tn}")
    print(f"⚠️ FP (Yanlış Alarm)     : {fp}")
    print("-" * 50)
    
    # Hata Analizi (Opsiyonel: Yanlış alarmların en çok olduğu URL'ler)
    if fp > 0:
        print("\n[INFO] En Sık Yanlış Alarm Veren (FP) URL'ler:")
        fp_rows = df[(y_true == 0) & (y_pred == 1)]
        print(fp_rows['path'].value_counts().head(5))

if __name__ == "__main__": main()