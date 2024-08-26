from elasticsearch import Elasticsearch
import pandas as pd
from datetime import datetime

def count_documents(es, index_pattern, start_time, end_time):
    # Define a query with a date range based on the input start_time and end_time
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}}
                ]
            }
        }
    }
    
    # Execute the count query
    response = es.count(
        index=index_pattern,
        body=query  # Pass the entire query object as the body
    )
    return response['count']

def evaluate_ids(es, snort_index_pattern, suricata_index_pattern, start_time, end_time):
    # Convert datetime to string in the format Elasticsearch expects
    start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%S')
    end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%S')
    
    # Count documents from Elasticsearch
    snort_count = count_documents(es, snort_index_pattern, start_time_str, end_time_str)
    suricata_count = count_documents(es, suricata_index_pattern, start_time_str, end_time_str)
    
    # Compile metrics
    metrics = {
        "detection_accuracy": {},
        "true_positives": {"snort": snort_count, "suricata": suricata_count},
        "false_negatives": {}
    }
    
    # Generate recommendation based on the metrics
    recommendation = "Based on calculated metrics, choose Snort or Suricata."

    return metrics, recommendation

# Example usage
es = Elasticsearch(
    ['http://localhost:9200'],
    timeout=30,
    max_retries=10,
    retry_on_timeout=True
)  # Adjust connection settings as necessary

start_time = datetime(2024, 8, 1, 19, 30)  # Start of the time range
end_time = datetime(2024, 8, 12, 20, 30)    # End of the time range

try:
    metrics, recommendation = evaluate_ids(es, 'filebeat-7.12.1-*', 'filebeat-7.17.23-*', start_time, end_time)
    print("Metrics:\n", metrics)
    print("\nRecommendation:\n", recommendation)
except Exception as e:
    print("An error occurred:", e)
