from elasticsearch import Elasticsearch
from datetime import datetime

def fetch_precision_data(es, index_pattern, agent_details, start_time, end_time, message_content):
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
                "must": common_query + [{"match_phrase": {"message": message_content}}]
            }
        }

        fp_query = {
            "bool": {
                "must": common_query,
                "must_not": [{"match_phrase": {"message": message_content}}]
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

        results[agent_name] = {
            "precision": precision,
            "true_positives": true_positives,
            "false_positives": false_positives
        }

    return results

def evaluate_ids_precision(es, start_time, end_time, message_content):
    agent_details = [
        ("SnortVM", "filebeat", "7.12.1", "/usr/local/snort/var/log/alert_fast.txt"),
        ("SuricataVM", "filebeat", "7.17.23", "/var/log/suricata/fast.log")
    ]

    # Calculate precision for both Snort and Suricata
    precisions = fetch_precision_data(es, 'filebeat-*', agent_details, start_time, end_time, message_content)

    # Determine the recommendation based on precision
    snort_precision = precisions["SnortVM"]["precision"]
    suricata_precision = precisions["SuricataVM"]["precision"]

    if snort_precision > suricata_precision:
        recommendation = "Recommendation: Choose Snort"
    elif suricata_precision > snort_precision:
        recommendation = "Recommendation: Choose Suricata"
    else:
        recommendation = "Recommendation: Choose either Snort or Suricata"

    return precisions, recommendation

# Main block to handle user input and execute
if __name__ == "__main__":
    es = Elasticsearch(['http://localhost:9200'])
    
    message_content = input("Enter the attack type to search for in the message field: ")
    start_input = input("Enter the start date and time in the following format (YYYY-MM-DDTHH:MM:SSZ): ")
    end_input = input("Enter the end date and time in the following format (YYYY-MM-DDTHH:MM:SSZ): ")

    try:
        precisions, recommendation = evaluate_ids_precision(es, start_input, end_input, message_content)
        for agent, data in precisions.items():
            print(f"{agent} Precision: {data['precision']:.2f}%")
            print(f"True Positives for {agent}: {data['true_positives']}")
            print(f"False Positives for {agent}: {data['false_positives']}")
        print(recommendation)
    except Exception as e:
        print(f"An error occurred: {e}")