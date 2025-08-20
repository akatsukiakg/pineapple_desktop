"""Utilities to forward requests to Burp via proxy (HTTP)"""
from __future__ import annotations
import requests
from typing import Dict, Any, Optional

class BurpForwarder:
    def __init__(self, proxy_url: str = "http://127.0.0.1:8080"):
        self.proxy = {
            'http': proxy_url,
            'https': proxy_url,
        }

    def forward_get(self, url: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
        return requests.get(url, params=params, proxies=self.proxy, verify=False)

    def forward_post(self, url: str, data: Optional[Dict[str, Any]] = None, json: Optional[Dict[str, Any]] = None) -> requests.Response:
        return requests.post(url, data=data, json=json, proxies=self.proxy, verify=False)
