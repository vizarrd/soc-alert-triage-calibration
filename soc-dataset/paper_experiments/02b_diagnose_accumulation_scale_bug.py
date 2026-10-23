import re
import pandas as pd
import numpy as np

df = pd.read_csv('wazuh_soc_dataset.csv')
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
r4_mask = df['timestamp'] >= pd.Timestamp('2026-09-14 12:00:00', tz='UTC')

def accumulation_score(frame, window_minutes=10):
    frame = frame.sort_values('timestamp').copy()
    scores = []
    ips = frame['src_ip'].fillna('unknown').values
    times = frame['timestamp'].values
    window = np.timedelta64(window_minutes, 'm')
    for i in range(len(frame)):
        t0 = times[i]
        ip = ips[i]
        mask = (ips[:i+1] == ip) & (times[:i+1] > t0 - window) & (times[:i+1] <= t0)
        scores.append(mask.sum())
    frame['accumulation'] = scores
    return frame

train_df = accumulation_score(df[~r4_mask].dropna(subset=['is_true_positive']).copy())
test_df = accumulation_score(df[r4_mask].dropna(subset=['is_true_positive']).copy())

print("Train (rounds 1-3) accumulation score stats:")
print(train_df['accumulation'].describe())
print("\nTest (round 4) accumulation score stats:")
print(test_df['accumulation'].describe())
print("\nTrain accumulation percentiles:", np.percentile(train_df['accumulation'], [50,75,90,95,99]))
print("Test accumulation percentiles:", np.percentile(test_df['accumulation'], [50,75,90,95,99]))
