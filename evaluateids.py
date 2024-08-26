import pandas as pd

def evaluate_ids(snort_log_path, suricata_log_path):
    # Define column names
    columns = ["timestamp", "signature_id", "alert_message", "priority", "protocol", "src_ip", "src_port", "dst_ip", "dst_port"]
    
    # Load the logs into DataFrames
    snort_df = pd.read_csv(snort_log_path, sep=" ", header=None, names=columns, usecols=[0, 1, 2, 3, 4, 5, 6, 7, 8])
    suricata_df = pd.read_csv(suricata_log_path, sep=" ", header=None, names=columns, usecols=[0, 1, 2, 3, 4, 5, 6, 7, 8])
    
    # Metrics calculation
    metrics = {
        "detection_volume": {},
        "alert_redundancy": {},
        "log_format": {}
    }
    
    # Detection Volume
    metrics["detection_volume"]["snort"] = len(snort_df)
    metrics["detection_volume"]["suricata"] = len(suricata_df)
    
    # Alert Redundancy (number of unique alerts vs. total alerts)
    snort_unique_alerts = snort_df.drop_duplicates(subset=["signature_id", "alert_message", "src_ip", "src_port", "dst_ip", "dst_port"])
    suricata_unique_alerts = suricata_df.drop_duplicates(subset=["signature_id", "alert_message", "src_ip", "src_port", "dst_ip", "dst_port"])
    
    metrics["alert_redundancy"]["snort"] = len(snort_unique_alerts) / len(snort_df)
    metrics["alert_redundancy"]["suricata"] = len(suricata_unique_alerts) / len(suricata_df)
    
    # Log Format (checking for completeness of the columns)
    metrics["log_format"]["snort"] = snort_df.notnull().sum().sum() / (len(snort_df) * len(columns))
    metrics["log_format"]["suricata"] = suricata_df.notnull().sum().sum() / (len(suricata_df) * len(columns))
    
    # Recommendation logic
    recommendation = ""
    
    if metrics["detection_volume"]["snort"] > metrics["detection_volume"]["suricata"]:
        recommendation += "Snort has a higher detection volume.\n"
    else:
        recommendation += "Suricata has a higher detection volume.\n"
    
    if metrics["alert_redundancy"]["snort"] < metrics["alert_redundancy"]["suricata"]:
        recommendation += "Snort has higher alert redundancy.\n"
    else:
        recommendation += "Suricata has higher alert redundancy.\n"
    
    if metrics["log_format"]["snort"] > metrics["log_format"]["suricata"]:
        recommendation += "Snort log format is more complete.\n"
    else:
        recommendation += "Suricata log format is more complete.\n"
    
    if recommendation.count("Snort") > recommendation.count("Suricata"):
        recommendation += "\nOverall, Snort is recommended based on these logs."
    else:
        recommendation += "\nOverall, Suricata is recommended based on these logs."
    
    return metrics, recommendation

# Example usage:
snort_log_path = r'C:\Users\OLUWATOSIN ADEYEMO\Downloads/alert_fast.txt'
suricata_log_path = r'C:\Users\OLUWATOSIN ADEYEMO\Downloads/fast.log'
metrics, recommendation = evaluate_ids(snort_log_path, suricata_log_path)

print("Metrics:\n", metrics)
print("\nRecommendation:\n", recommendation)
