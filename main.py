import requests
import json
import datetime
from elasticsearch import Elasticsearch
from time import sleep
import os
import logging
from pathlib import Path
from urllib.parse import urlparse
from dotenv import load_dotenv
from elasticsearch.helpers import bulk

# Load environment variables from .env file if present
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cve_importer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def get_env_var(name, default=None):
    """Safely get environment variable with debug logging."""
    value = os.getenv(name, default)
    if value is None:
        logger.debug(f"Environment variable {name} is not set")
    else:
        logger.debug(f"Environment variable {name} is set (value hidden for security)")
    return value

# Configuration
CONFIG = {
    'NVD_API_KEY': get_env_var('NVD_API_KEY', ''),
    'NVD_BASE_URL': 'https://services.nvd.nist.gov/rest/json/cves/2.0/',
    'ELASTIC_CLOUD_ID': get_env_var('ELASTIC_CLOUD_ID'),
    'ELASTIC_API_KEY': get_env_var('ELASTIC_API_KEY'),
    'ELASTIC_USERNAME': get_env_var('ELASTIC_USERNAME'),
    'ELASTIC_PASSWORD': get_env_var('ELASTIC_PASSWORD'),
    'ELASTIC_INDEX': get_env_var('ELASTIC_INDEX', 'nvd_cves'),
    'STATE_FILE': get_env_var('STATE_FILE', 'last_successful_run.txt'),
    'INITIAL_DAYS': int(get_env_var('INITIAL_DAYS', '7')),
    'RATE_LIMIT_DELAY': int(get_env_var('RATE_LIMIT_DELAY', '6')),
    'BATCH_SIZE': int(get_env_var('BATCH_SIZE', '100')),
}

def validate_config():
    """Validate required configuration is present."""
    errors = []
    
    if not CONFIG['ELASTIC_CLOUD_ID']:
        errors.append("ELASTIC_CLOUD_ID is required")
    
    if not CONFIG['ELASTIC_API_KEY'] and not (CONFIG['ELASTIC_USERNAME'] and CONFIG['ELASTIC_PASSWORD']):
        errors.append("Either ELASTIC_API_KEY or both ELASTIC_USERNAME and ELASTIC_PASSWORD are required")
    
    if errors:
        logger.error("Configuration errors:\n" + "\n".join(errors))
        return False
    return True

def get_last_successful_run():
    """Get the timestamp of the last successful run from the state file."""
    try:
        with open(CONFIG['STATE_FILE'], 'r') as f:
            return datetime.datetime.fromisoformat(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None

def update_last_successful_run():
    """Update the state file with the current timestamp."""
    Path(CONFIG['STATE_FILE']).parent.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.utcnow().replace(microsecond=0)
    with open(CONFIG['STATE_FILE'], 'w') as f:
        f.write(now.isoformat())
    return now

def calculate_start_date(last_run):
    """Calculate the start date for CVE retrieval."""
    if last_run is None:
        return (datetime.datetime.utcnow() - datetime.timedelta(days=CONFIG['INITIAL_DAYS'])).date()
    else:
        return last_run.date()

def fetch_cves_from_nvd(start_date, end_date=None):
    """Fetch CVEs from NVD API for the given date range."""
    if end_date is None:
        end_date = datetime.datetime.utcnow().date()
    
    start_datetime = datetime.datetime.combine(start_date, datetime.time.min)
    end_datetime = datetime.datetime.combine(end_date, datetime.time.max)
    
    params = {
        'pubStartDate': start_datetime.isoformat(timespec='seconds') + 'Z',
        'pubEndDate': end_datetime.isoformat(timespec='seconds') + 'Z',
        'resultsPerPage': 2000
    }
    
    headers = {}
    if CONFIG['NVD_API_KEY']:
        headers['apiKey'] = CONFIG['NVD_API_KEY']
    
    try:
        logger.info(f"Fetching CVEs from {start_date} to {end_date}")
        response = requests.get(
            CONFIG['NVD_BASE_URL'],
            params=params,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        
        data = response.json()
        total_results = data.get('totalResults', 0)
        vulnerabilities = data.get('vulnerabilities', [])
        
        logger.info(f"Retrieved {len(vulnerabilities)} of {total_results} CVEs")
        
        while len(vulnerabilities) < total_results:
            sleep(CONFIG['RATE_LIMIT_DELAY'])
            params['startIndex'] = len(vulnerabilities)
            response = requests.get(
                CONFIG['NVD_BASE_URL'],
                params=params,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            vulnerabilities.extend(data.get('vulnerabilities', []))
            logger.info(f"Retrieved {len(vulnerabilities)} of {total_results} CVEs")
        
        return vulnerabilities
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching CVEs from NVD: {e}")
        return None

def connect_elasticsearch():
    """Create and return Elasticsearch connection for Elastic Cloud."""
    try:
        es_args = {
            'cloud_id': CONFIG['ELASTIC_CLOUD_ID'],
            'request_timeout': 30,
            'max_retries': 3,
            'retry_on_timeout': True
        }
        
        if CONFIG['ELASTIC_API_KEY']:
            es_args['api_key'] = CONFIG['ELASTIC_API_KEY']
        else:
            es_args['basic_auth'] = (CONFIG['ELASTIC_USERNAME'], CONFIG['ELASTIC_PASSWORD'])
        
        es = Elasticsearch(**es_args)
        
        if es.ping():
            logger.info("Connected to Elastic Cloud")
            return es
        else:
            logger.error("Could not connect to Elastic Cloud")
            return None
    except Exception as e:
        logger.error(f"Error connecting to Elastic Cloud: {e}")
        return None

def create_index_if_not_exists(es):
    """Create the Elasticsearch index if it doesn't exist."""
    if not es.indices.exists(index=CONFIG['ELASTIC_INDEX']):
        try:
            mapping = {
                "mappings": {
                    "properties": {
                        "cve": {
                            "properties": {
                                "id": {"type": "keyword"},
                                "published": {"type": "date"},
                                "lastModified": {"type": "date"},
                                "vulnStatus": {"type": "keyword"},
                                "descriptions": {
                                    "type": "nested",
                                    "properties": {
                                        "lang": {"type": "keyword"},
                                        "value": {
                                            "type": "text",
                                            "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}
                                        }
                                    }
                                },
                                "metrics": {"type": "object", "enabled": True},
                                "weaknesses": {"type": "nested"},
                                "configurations": {"type": "nested"},
                                "references": {"type": "nested"}
                            }
                        }
                    }
                },
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1
                }
            }
            es.indices.create(index=CONFIG['ELASTIC_INDEX'], body=mapping)
            logger.info(f"Created index {CONFIG['ELASTIC_INDEX']}")
        except Exception as e:
            logger.error(f"Error creating index: {e}")

def index_cves_to_elasticsearch(es, cves):
    """Index CVEs to Elasticsearch using bulk API."""
    if not es or not cves:
        return False
    
    try:
        create_index_if_not_exists(es)
        
        operations = []
        for cve_item in cves:
            cve_id = cve_item['cve']['id']
            operations.append({
                '_op_type': 'index',
                '_index': CONFIG['ELASTIC_INDEX'],
                '_id': cve_id,
                '_source': cve_item
            })
        
        success_count = 0
        for i in range(0, len(operations), CONFIG['BATCH_SIZE']):
            batch = operations[i:i + CONFIG['BATCH_SIZE']]
            try:
                success, _ = bulk(es, batch)
                success_count += success
                logger.info(f"Indexed batch {i//CONFIG['BATCH_SIZE'] + 1}, total indexed: {success_count}")
            except Exception as e:
                logger.error(f"Error indexing batch starting at {i}: {e}")
        
        logger.info(f"Successfully indexed {success_count} of {len(cves)} CVEs")
        return success_count > 0
    
    except Exception as e:
        logger.error(f"Error indexing CVEs: {e}")
        return False

def main():
    """Main function to orchestrate the CVE import process."""
    logger.info("Starting CVE import process")
    
    if not validate_config():
        return False
    
    last_run = get_last_successful_run()
    start_date = calculate_start_date(last_run)
    
    cves = fetch_cves_from_nvd(start_date)
    if not cves:
        logger.error("No CVEs retrieved from NVD")
        return False
    
    es = connect_elasticsearch()
    if not es:
        return False
    
    success = index_cves_to_elasticsearch(es, cves)
    if success:
        update_last_successful_run()
        logger.info("CVE import completed successfully")
    else:
        logger.error("CVE import failed")
    
    return success

if __name__ == "__main__":
    main()