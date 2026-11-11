#!/bin/bash
# Script a executer dans le root shell TV pour remapper Home -> Mon Accueil
# Usage: copier-coller ces commandes dans le shell root

echo "=== Backup des valeurs actuelles ==="
vconftool get db/appfw/home_appid 2>&1 || echo "(cle absente)"
vconftool get db/appfw/startup_appid 2>&1 || echo "(cle absente)"

echo ""
echo "=== Remap Home -> MonAccueil.Launcher ==="
vconftool set -t string db/appfw/home_appid MonAccueil.Launcher -f
vconftool set -t string db/appfw/startup_appid MonAccueil.Launcher -f

echo ""
echo "=== Verification ==="
vconftool get db/appfw/home_appid
vconftool get db/appfw/startup_appid

echo ""
echo "DONE. Retire la cle USB et redemarre la TV pour tester."
