from elasticsearch import Elasticsearch
from datetime import datetime

def fetch_precision_data(es, index_pattern, agent_details, start_time, end_time):
    results = {}
    for agent_name, agent_type, agent_version, log_path in agent_details:
        # Define queries for True Positives and False Positives
        common_query = [
            {"match_phrase": {"agent.name": agent_name}},
            {"match": {"agent.type": agent_type}},
            {"match": {"agent.version": agent_version}},
            {"match_phrase": {"log.file.path": log_path}},  # Specific log file path
            {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}}
        ]

        tp_query = {
            "bool": {
                "must": common_query + [{"match_phrase": {"message": "Nmap SYN scan detected"}}]
            }
        }
        
        fp_query = {
            "bool": {
                "must": common_query,
                "must_not": [{"match_phrase": {"message": "Nmap SYN scan detected"}}]
            }
        }
        
        # Execute count queries for TP and FP
        true_positives = es.count(index=index_pattern, body={"query": tp_query})['count']
        false_positives = es.count(index=index_pattern, body={"query": fp_query})['count']
        
        # Calculate precision if applicable
        if (true_positives + false_positives) > 0:
            precision = (true_positives / (true_positives + false_positives)) * 100  # Convert to percentage
        else:
            precision = 0  # Set precision to 0% if no positives found
        results[agent_name] = precision
    
    return results

def evaluate_ids_precision(es, start_time, end_time):
    agent_details = [
        ("SnortVM", "filebeat", "7.12.1", "/usr/local/snort/var/log/alert_fast.txt"),  # Specific log path for Snort
        ("SuricataVM", "filebeat", "7.17.23", "/var/log/suricata/fast.log")  # Specific log path for Suricata
    ]
    
    # Calculate precision for both Snort and Suricata
    precisions = fetch_precision_data(es, 'filebeat-*', agent_details, start_time, end_time)
    
    # Making recommendation based on precision
    snort_precision = precisions["SnortVM"]
    suricata_precision = precisions["SuricataVM"]
    
    if snort_precision > suricata_precision:
        recommendation = "Choose Snort"
    elif suricata_precision > snort_precision:
        recommendation = "Choose Suricata"
    else:
        recommendation = "Choose either Snort or Suricata"
    
    return snort_precision, suricata_precision, recommendation

# Example usage
es = Elasticsearch(['http://localhost:9200'])

start_time = '2024-08-28T13:00:00Z'  # Start of the specified time range
end_time = '2024-08-28T13:15:00Z'    # End of the specified time range

try:
    snort_precision, suricata_precision, recommendation = evaluate_ids_precision(es, start_time, end_time)
    print(f"Snort Precision: {snort_precision:.2f}%")
    print(f"Suricata Precision: {suricata_precision:.2f}%")
    print(recommendation)
except Exception as e:
    print(f"An error occurred: {e}")