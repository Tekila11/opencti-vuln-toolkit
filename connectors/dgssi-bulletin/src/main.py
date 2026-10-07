#!/usr/bin/env python3
import os
import yaml
from connector import DgssiBulletinConnector

if __name__ == "__main__":
    config_path = os.path.join(os.path.dirname(__file__), "config.yml")
    config = (
        yaml.load(open(config_path), Loader=yaml.SafeLoader)
        if os.path.isfile(config_path)
        else {}
    )
    connector = DgssiBulletinConnector(config)
    connector.run()
