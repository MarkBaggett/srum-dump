import json
import yaml
import logging # Added for logging
from typing import Dict, Any

# --- Logger Setup ---
# Note: Using class name directly here as it's the primary component
logger = logging.getLogger(f"srum_dump.ConfigManager")
# --- End Logger Setup ---

class ConfigManager:
    def __init__(self, file_path: str, file_format: str = "json"):
        """
        Initialize the ConfigManager.
        :param file_path: Path to the configuration file.
        :param file_format: File format, either 'json' or 'yaml'.
        """
        logger.debug(f"Initializing ConfigManager with file_path: {file_path}, file_format: {file_format}")
        try:
            if file_format not in {"json", "yaml"}:
                err_msg = f"Unsupported file format '{file_format}'. Use 'json' or 'yaml'."
                logger.error(err_msg)
                raise ValueError(err_msg)

            self.file_path = file_path
            self.file_format = file_format
            self.data: Dict[str, Dict[str, Any]] = {}
            self.load() # Load data during initialization
            logger.debug("ConfigManager initialized successfully.")
        except Exception as e:
            logger.exception(f"Error during ConfigManager initialization: {e}")
            # Re-raise the exception after logging
            raise

    def load(self) -> None:
        """Load configuration from the file."""
        logger.debug(f"Attempting to load config from: {self.file_path} (format: {self.file_format})")
        original_data = self.data # Keep a copy in case load fails partially? Not really feasible here.
        try:
            with open(self.file_path, "r", encoding="utf-8") as file:
                if self.file_format == "json":
                    loaded_data = json.load(file)
                    logger.debug("Loaded data using json.load")
                else: # yaml
                    loaded_data = yaml.safe_load(file)
                    logger.debug("Loaded data using yaml.safe_load")

                # Ensure loaded data is a dictionary, default to empty if None (e.g., empty YAML file)
                self.data = loaded_data if isinstance(loaded_data, dict) else {}
                logger.info(f"Successfully loaded config from {self.file_path}. Found {len(self.data)} top-level keys.")

        except FileNotFoundError:
            self.data = {}
        except (json.JSONDecodeError, yaml.YAMLError) as decode_error:
            logger.exception(f"Error decoding config file {self.file_path}: {decode_error}. Initializing with empty data.")
            self.data = {} # Reset data on decode error
        except Exception as e:
             logger.exception(f"Unexpected error loading config file {self.file_path}: {e}. Initializing with empty data.")
             self.data = {} # Reset data on other errors

    def save(self) -> None:
        """Save configuration to the file."""
        logger.debug(f"Attempting to save config to: {self.file_path} (format: {self.file_format})")
        try:
            # Ensure parent directory exists (optional, but good practice)
            # pathlib.Path(self.file_path).parent.mkdir(parents=True, exist_ok=True)

            with open(self.file_path, "w", encoding="utf-8") as file:
                if self.file_format == "json":
                    json.dump(self.data, file, indent=4)
                    logger.debug("Saved data using json.dump")
                else: # yaml
                    yaml.safe_dump(self.data, file, default_flow_style=False)
                    logger.debug("Saved data using yaml.safe_dump")
            logger.info(f"Successfully saved config to {self.file_path}")
        except Exception as e:
            logger.exception(f"Error saving config file {self.file_path}: {e}")
            # Decide if we should raise the error or just log it
            # raise # Option: re-raise the exception

    def set_config(self, name: str, config: Dict[str, Any]) -> None:
        """Set a configuration dictionary."""
        logger.debug(f"Setting config for name: '{name}'")
        # Log config content cautiously, maybe just keys or type/length
        logger.debug(f"Config data type: {type(config)}, Keys (if dict): {list(config.keys()) if isinstance(config, dict) else 'N/A'}")
        try:
            self.data[name] = config
            self.save() # Save after setting
            logger.info(f"Successfully set and saved config for '{name}'.")
        except Exception as e:
             logger.exception(f"Error setting config for '{name}': {e}")
             # Optionally revert or handle error

    def get_config(self, name: str) -> Dict[str, Any]:
        """Retrieve a configuration dictionary."""
        logger.debug(f"Getting config for name: '{name}'")
        config_data = self.data.get(name, {})
        # Log retrieved data cautiously
        logger.debug(f"Retrieved config for '{name}'. Type: {type(config_data)}, Keys (if dict): {list(config_data.keys()) if isinstance(config_data, dict) else 'N/A'}")
        return config_data

    def delete_config(self, name: str) -> None:
        """Delete a configuration dictionary."""
        logger.debug(f"Attempting to delete config for name: '{name}'")
        try:
            if name in self.data:
                del self.data[name]
                logger.info(f"Deleted config entry '{name}' from internal data.")
                self.save() # Save after deleting
                logger.info(f"Successfully deleted and saved config for '{name}'.")
            else:
                logger.warning(f"Config name '{name}' not found, nothing to delete.")
        except Exception as e:
            logger.exception(f"Error deleting config for '{name}': {e}")
            # Optionally handle error

    def list_configs(self) -> list:
        """List all configuration names."""
        logger.debug("Listing all config names.")
        config_keys = list(self.data.keys())
        logger.debug(f"Returning config keys: {config_keys}")
        return config_keys
