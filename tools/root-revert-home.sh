#!/bin/bash
# Script pour ANNULER le remap et revenir au Smart Hub Samsung
# Usage: copier-coller dans le shell root en cas de probleme

vconftool set -t string db/appfw/home_appid org.tizen.hbbtv-app -f
vconftool set -t string db/appfw/startup_appid org.tizen.hbbtv-app -f

echo "Reverted to Samsung Smart Hub. Redemarrer la TV."
