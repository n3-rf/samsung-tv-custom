#!/usr/bin/env python3
"""
Lance l'app "Mon Accueil" (MonAccueil.Launcher) sur la TV Samsung via l'API
officielle de télécommande Samsung (WebSocket), fournie par Samsung lui-même.

AUCUN root, AUCun contournement : c'est le même canal que l'app SmartThings.

Principe :
  1. On se connecte en WSS au canal "samsung.remote.control".
  2. La 1re fois, la TV affiche "Autoriser cet appareil ?" -> réponds Autoriser.
     La TV renvoie alors un TOKEN qu'on enregistre dans token.txt (à côté de ce script).
  3. Les fois suivantes, on réutilise le token (plus aucune pop-up).
  4. On émet l'évènement ed.apps.launch avec l'appId du lanceur.

Dépendance : pip install websocket-client

Usage :
  python launch-mon-accueil.py                      # lance Mon Accueil
  python launch-mon-accueil.py <AUTRE.AppId>         # lance une autre app

Idée finale : relie ce script à un bouton physique (Flic, ESP32, Stream Deck,
raccourci clavier, vieux téléphone...) et tu as "1 appui -> ton accueil".
"""

import sys
import os
import ssl
import json
import base64
import time

try:
    import websocket  # websocket-client
except ImportError:
    sys.exit("Installe la dépendance d'abord :  pip install websocket-client")

TV_IP   = "192.168.1.23"
PORT    = 8002                       # 8002 = WSS (TLS), requis pour l'auth par token
APP_ID  = sys.argv[1] if len(sys.argv) > 1 else "MonAccueil.Launcher"
NAME    = "MonAccueilBtn"            # nom affiché dans la pop-up d'autorisation TV
TOKEN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "token.txt")


def load_token():
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            return f.read().strip() or None
    except FileNotFoundError:
        return None


def save_token(tok):
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        f.write(tok)


def build_url(token):
    name_b64 = base64.b64encode(NAME.encode()).decode()
    url = f"wss://{TV_IP}:{PORT}/api/v2/channels/samsung.remote.control?name={name_b64}"
    if token:
        url += f"&token={token}"
    return url


def launch():
    token = load_token()
    url = build_url(token)
    if not token:
        print("1re connexion : va sur la TV et accepte la demande "
              "« Autoriser MonAccueilBtn ? » dans les 60 s.")
    # Le certificat de la TV est auto-signé : on désactive la vérif TLS pour CE LAN.
    # 60 s : laisse le temps d'accepter la pop-up d'autorisation la 1re fois.
    ws = websocket.create_connection(url, sslopt={"cert_reqs": ssl.CERT_NONE}, timeout=60)

    got_token = None
    launched = False
    try:
        # 1er message = ms.channel.connect ; il peut contenir un nouveau token.
        for _ in range(6):
            raw = ws.recv()
            if not raw:
                continue
            msg = json.loads(raw)
            event = msg.get("event", "")
            if event == "ms.channel.connect":
                data = msg.get("data") or {}
                got_token = data.get("token")
                if got_token and got_token != token:
                    save_token(got_token)
                    print(f"Token enregistré dans {TOKEN_FILE}")
                # Canal prêt -> on lance l'app
                payload = {
                    "method": "ms.channel.emit",
                    "params": {
                        "event": "ed.apps.launch",
                        "to": "host",
                        "data": {
                            "appId": APP_ID,
                            "action_type": "NATIVE_LAUNCH",
                        },
                    },
                }
                ws.send(json.dumps(payload))
                launched = True
                time.sleep(0.5)
                break
            elif event in ("ms.channel.unauthorized", "ms.channel.timeOut"):
                sys.exit("Autorisation refusée/expirée sur la TV. Relance et choisis 'Autoriser'.")
    finally:
        ws.close()

    if launched:
        print(f"Commande de lancement envoyée : {APP_ID}")
    else:
        print("Connexion établie mais lancement non confirmé — réessaie.")


if __name__ == "__main__":
    launch()
