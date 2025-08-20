Pineapple Desktop Project (Python)



<pre>

python -m src.app
<pre>

Objective:
Desktop application in Python to control and automate a WiFi Pineapple.
Includes SSH connection, PineAP command execution, integration with Wireshark (tshark), and Burp Suite.

Structure:

<pre> 
  pineapple_desktop/
├── README.md               
├── requirements.txt        
├── src/                  
│   ├── __init__.py
│   ├── app.py              # GUI launcher
│   ├── core/               # Núcleo lógico del programa
│   │   ├── __init__.py
│   │   ├── pineapple.py    # SSH logic and PineAP commands
│   │   ├── capture.py      # Wireshark/tshark integration
│   │   └── burp.py         # Proxy/forward utilities for Burp
│   └── ui/                 # Interfaz gráfica (tkinter)
│       ├── __init__.py
│       └── main_window.py  # Basic GUI (tkinter)
├── tests/                  
│   ├── __init__.py
│   ├── test_pineapple.py  
│   ├── test_capture.py     
│   └── test_burp.py   
</pre>


Requirements:

Python 3.10+

paramiko

requests

tkinter

pytest (dev)

Next step: Install dependencies and run the sample app.
