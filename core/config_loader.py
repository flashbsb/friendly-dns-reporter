import os
import configparser

class Settings:
    """Helper class to load and access settings safely from settings.ini."""
    def __init__(self, config_path="config/settings.ini"):
        self.config = configparser.ConfigParser()
        self.path = config_path
        if os.path.exists(config_path):
            self.config.read(config_path, encoding='utf-8')
        
    def get_int(self, section, key, fallback):
        return self.config.getint(section, key, fallback=fallback)
    
    def get_str(self, section, key, fallback):
        return self.config.get(section, key, fallback=fallback)
    
    def get_bool(self, section, key, fallback):
        return self.config.getboolean(section, key, fallback=fallback)
    
    def get_float(self, section, key, fallback):
        return self.config.getfloat(section, key, fallback=fallback)

    # --- GENERAL ---
    @property
    def max_threads(self):
        return self.get_int("GENERAL", "MAX_THREADS", 10)

    @property
    def timeout(self):
        return self.get_int("GENERAL", "TIMEOUT", 4)

    @property
    def sleep_time(self):
        return self.get_float("GENERAL", "SLEEP", 0.01)

    # --- REPORTS ---
    @property
    def log_dir(self):
        return self.get_str("REPORTS", "LOG_DIR", "logs")

    # --- CONNECTIVITY ---
    @property
    def enable_ping(self):
        return self.get_bool("CONNECTIVITY", "ENABLE_PING", True)

    @property
    def ping_count(self):
        return self.get_int("CONNECTIVITY", "PING_COUNT", 3)

    # --- ADVANCED CHECKS ---
    @property
    def check_bind_version(self):
        return self.get_bool("ADVANCED_CHECKS", "CHECK_BIND_VERSION", True)

    @property
    def enable_recursion_check(self):
        return self.get_bool("ADVANCED_CHECKS", "ENABLE_RECURSION_CHECK", True)

    @property
    def enable_dnssec_check(self):
        return self.get_bool("ADVANCED_CHECKS", "ENABLE_DNSSEC_CHECK", True)

    @property
    def enable_dot_check(self):
        return self.get_bool("ADVANCED_CHECKS", "ENABLE_TLS_CHECK", True) # Using ENABLE_TLS_CHECK mapping

    @property
    def enable_doh_check(self):
        return self.get_bool("ADVANCED_CHECKS", "ENABLE_DOH_CHECK", True)

    # --- CONSISTENCY ---
    @property
    def consistency_checks(self):
        return self.get_int("CONSISTENCY", "CONSISTENCY_CHECKS", 1)
