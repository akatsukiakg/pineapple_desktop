Pineapple Desktop Project (Python)

Objective:

Desktop application in Python to control and automate a WiFi Pineapple.

SSH connection, execution of PineAP commands, integration with Wireshark (tshark) and Burp Suite.

Structure:

pineapple_desktop/

README.md

requirements.txt

src/

__init__.py

app.py # GUI launcher

core/

__init__.py

pineapple.py # SSH logic and PineAP commands

capture.py # tshark/wireshark integration

burp.py # Proxy/forward utilities for Burp

ui/

__init__.py

main_window.py # Basic GUI (tkinter)

tests/

Requirements:

Python 3.10+

paramiko

requests

tkinter

pytest (dev)

