import yaml

# Load configuration from config.yaml
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

# Get the list of directories to monitor from the config
INTEGRITY_DIRS = config["monitoring"]["integrity"]
ACTIVITY_DIRS = config["monitoring"]["activity"]

# Get the path to the baseline data
BASELINE_PATH = config["data"]["baseline_path"]

# Get the path to the log file
LOG_FILE = config["data"]["log_file"]
