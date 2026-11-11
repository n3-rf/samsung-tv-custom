# Exploration TV - Resultats (session root shell)

## Mecanisme Home Button - Pistes

### 1. org.tizen.menu (PISTE PRINCIPALE)
- **App ID**: `org.tizen.menu`
- **Binary**: `/usr/apps/org.tizen.menu/bin/menu`
- **Version**: 0.3.4 (RPM, preload)
- **Ressources**: `/usr/apps/org.tizen.menu/res/` → edje, images, json
- C'est probablement l'app lancee par le bouton Home (le "Smart Hub")

### 2. TV Context Manager (tvctx-manager)
- `/etc/tvctx-manager/appctx-config.json` — config avec ref a org.tizen.menu
- `/etc/tvctx-manager/.app-context.db` — base de donnees des contextes d'apps
- `/etc/tvctx-manager/launcher/` — configs de lancement par sequence de touches
- **A EXPLORER**: le contenu de appctx-config.json

### 3. Enlightenment (Window Manager)
- PID 222: `/usr/bin/enlightenment` (root)
- Modules cles:
  - `e-mod-tizen-keyrouter-tv` — routage des touches telecommande
  - `e-mod-tizen-wm-policy` — politique du WM
  - `e-mod-tizen-tvs-helper-tv` — helper TV
- Config: `/usr/share/enlightenment/data/config/tizen-tv/`
  - `e_bindings.cfg` — bindings (format binaire .eet)
  - `module.keyrouter.cfg` — config keyrouter (binaire)
  - `module.policy-tizen.cfg` — politique
- **strings** sur les modules.so → rien (binaires stripped)
- **grep "org.tizen.menu"** dans /usr/lib/enlightenment/ → rien
  → Le WM ne reference pas directement l'app menu

### 4. Buxton2 (key-value store)
- `/etc/buxton2/memory.db` contient ref a org.tizen.menu
- **A EXPLORER**: buxton2ctl list-keys pour trouver les cles home/menu

### 5. Ce qui NE controle PAS le Home button
- `db/appfw/home_appid` — N'existe pas sur cette TV
- `db/appfw/startup_appid` — N'existe pas non plus
- Ces cles vconf ne sont pas le mecanisme Tizen 4.0

## Apps identifiees
- `aQjWjLsPaO` = "App Launcher" (wgt, v3.2.15)
- `org.tizen.menu` = "menu" (rpm, v0.3.4) → SMART HUB
- `xvvl3S1TT1` = TizenTube/YouTube
- `NRi6kdBYJ0` = AirPlayWebApp
- `menu-smarthub` = juste des traductions (pas un vrai package)
- `MonAccueil` = notre app (deja installee dans /opt/usr/apps/)

## Commandes restantes a executer
```bash
cat /etc/tvctx-manager/appctx-config.json
ls /usr/apps/org.tizen.menu/res/json/
cat /usr/apps/org.tizen.menu/res/json/*.json | head -80
buxton2ctl list-keys system 2>/dev/null | grep -i -e menu -e home -e hub
grep -rl org.tizen.menu /usr/lib/*.so 2>/dev/null
```

## Notes pour la prochaine session
- Relancer les listeners (tools\listen.bat ou manuellement ports 4444+4445)
- Debrancher/rebrancher le SanDisk pour re-trigger l'exploit
- ATTENTION: ne pas utiliser de single quotes dans les commandes relay (casse bash)
- ATTENTION: ne pas utiliser sqlite3 avec du SQL dans le relay (probleme de quotes)
- Le relay fonctionne en append-only: toujours ajouter au fichier shell_cmds.txt, jamais ecraser
- Preparer les commandes a l'avance car la session root dure ~5-10min max

## Idees de remap (a tester)
1. Modifier `/etc/tvctx-manager/appctx-config.json` pour pointer Home vers MonAccueil
2. Modifier buxton2 keys si elles controlent le routage
3. Remplacer le binaire `/usr/apps/org.tizen.menu/bin/menu` par un wrapper qui lance MonAccueil
4. Modifier la config Enlightenment bindings (complexe, format .eet)
