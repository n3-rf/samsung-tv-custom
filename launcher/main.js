(function () {
  'use strict';

  var APPS = [
    { title: 'Netflix', id: 'RN1MCdNq8t.Netflix' },
    { title: 'YouTube', id: '9Ur5IzDKqV.TizenYouTube' },
    { title: 'TizenTube', id: 'xvvl3S1TT1.TizenTubeStandalone' },
    { title: 'Jellyfin', id: 'AprZAARz4r.Jellyfin' },
    { title: 'Prime Video', id: 'evKhCgZelL.AmazonIgnitionLauncher2' },
    { title: 'Disney+', id: 'MCmYXNxgcu.DisneyPlus' },
    { title: 'Twitch', id: 'Jz7aUrV2Q4.Twitch' },
    { title: 'Spotify', id: 'rJeHak5zRg.Spotify' },
    { title: 'TF1+', id: 'E0P3lRI4H7.MYTF1' },
    { title: 'M6+', id: 'Ol7HVEXtqh.6play' }
  ];
  var COLS = 4;
  var focus = 0;
  var grid = document.getElementById('grid');
  var statusEl = document.getElementById('status');
  var diagEl = document.getElementById('diag');
  var diagLines = [];

  function status(msg) { statusEl.textContent = msg; }
  function diag(msg) {
    diagLines.push(msg);
    if (diagLines.length > 6) { diagLines.shift(); }
    diagEl.textContent = diagLines.join('\n');
  }

  function render() {
    grid.innerHTML = '';
    APPS.forEach(function (app, i) {
      var d = document.createElement('div');
      d.className = 'tile' + (i === focus ? ' focus' : '');
      d.textContent = app.title;
      grid.appendChild(d);
    });
  }

  function move(dx, dy) {
    var n = focus + dx + dy * COLS;
    if (dx !== 0 && Math.floor(n / COLS) !== Math.floor(focus / COLS)) { return; }
    if (n < 0 || n >= APPS.length) { return; }
    focus = n;
    render();
  }

  function launch() {
    var app = APPS[focus];
    status('Lancement de ' + app.title + '…');
    try {
      tizen.application.launch(app.id, function () {
        status('');
      }, function (e) {
        status('Échec : ' + app.title + ' (' + e.name + ')');
      });
    } catch (e) {
      status('Erreur : ' + e.message);
    }
  }

  // Diagnostic : quelles touches la TV laisse-t-elle intercepter ?
  function probeKeys() {
    try {
      // Résultat du test (TV UE55NU7175) : 46 touches enregistrables, aucune de
      // type Home. On ne capture que Exit, pour que l'accueil ne se ferme pas.
      // Surtout ne pas enregistrer Volume/Chaînes : l'appli les avalerait.
      tizen.tvinputdevice.registerKey('Exit');
    } catch (e) {
      diag('tvinputdevice indisponible : ' + e.message);
    }
  }

  document.addEventListener('keydown', function (e) {
    switch (e.keyCode) {
      case 10182: /* Exit : on reste sur l'accueil */ break;
      case 37: move(-1, 0); break;
      case 38: move(0, -1); break;
      case 39: move(1, 0); break;
      case 40: move(0, 1); break;
      case 13: launch(); break;
      case 10009: /* Retour : on reste sur l'accueil */ break;
      default: return;
    }
    e.preventDefault();
  });

  function tick() {
    var d = new Date();
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    document.getElementById('clock').textContent = p(d.getHours()) + ':' + p(d.getMinutes());
  }

  render();
  tick();
  setInterval(tick, 10000);
  probeKeys();
})();
