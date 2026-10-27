"""Device side modules: discovery, pairing state, and app management.

Module ownership inside this package (all DEVICE agent):
    usbmux.py    device discovery and lockdown info via libimobiledevice
    installer.py install, uninstall, and listing via installation_proxy

The DEVICE agent never imports signing or auth modules; it consumes
IOSDevice and InstalledApp models only.
"""

from __future__ import annotations
