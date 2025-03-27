import json
import yaml
from typing import Dict, Any

class ConfigManager:
    def __init__(self, file_path: str, file_format: str = "json"):
        """
        Initialize the ConfigManager.
        :param file_path: Path to the configuration file.
        :param file_format: File format, either 'json' or 'yaml'.
        """
        if file_format not in {"json", "yaml"}:
            raise ValueError("Unsupported file format. Use 'json' or 'yaml'.")
        
        self.file_path = file_path
        self.file_format = file_format
        self.data: Dict[str, Dict[str, Any]] = {}
        self.load()
    
    def load(self) -> None:
        """Load configuration from the file."""
        try:
            with open(self.file_path, "r", encoding="utf-8") as file:
                if self.file_format == "json":
                    self.data = json.load(file)
                else:
                    self.data = yaml.safe_load(file) or {}
        except (FileNotFoundError, json.JSONDecodeError, yaml.YAMLError):
            self.data = {}
    
    def save(self) -> None:
        """Save configuration to the file."""
        with open(self.file_path, "w", encoding="utf-8") as file:
            if self.file_format == "json":
                json.dump(self.data, file, indent=4)
            else:
                yaml.safe_dump(self.data, file, default_flow_style=False)
    
    def set_config(self, name: str, config: Dict[str, Any]) -> None:
        """Set a configuration dictionary."""
        self.data[name] = config
        self.save()
    
    def get_config(self, name: str) -> Dict[str, Any]:
        """Retrieve a configuration dictionary."""
        return self.data.get(name, {})
    
    def delete_config(self, name: str) -> None:
        """Delete a configuration dictionary."""
        if name in self.data:
            del self.data[name]
            self.save()
    
    def list_configs(self) -> list:
        """List all configuration names."""
        return list(self.data.keys())
