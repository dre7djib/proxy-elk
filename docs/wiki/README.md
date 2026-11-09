# Documentation wiki (HTML)

Fichier principal : [`index.html`](index.html).

Ouvrir dans un navigateur pour prévisualiser :

```sh
xdg-open docs/wiki/index.html
# ou
python3 -m http.server 8765 --directory docs/wiki
```

## Publication sur le GitHub Wiki

Le wiki GitHub attend surtout du Markdown. Deux options :

1. **Page HTML telle quelle** — coller le contenu utile section par section dans des pages wiki (Home, Architecture, Authentification, ACL, …) en convertissant le HTML → Markdown, ou en gardant des blocs HTML supportés.
2. **Hébergement annexé** — conserver ce fichier dans le dépôt (`docs/wiki/`) et pointer le wiki Home vers ce chemin / une GitHub Pages.

Découpage suggéré pour le wiki :

| Page wiki | Ancre HTML |
| --- | --- |
| Home | `#top`, `#pourquoi`, `#principes`, `#roadmap` |
| Architecture | `#architecture` |
| Authentification | `#authentification` |
| ACL | `#acl` |
| Relais Elasticsearch | `#relais` |
| Configuration | `#configuration` |
| Déploiement | `#deploiement` |
| Démo | `#demo` |
| API | `#api` |
| Sécurité | `#securite` |

Sources de vérité du dépôt : `README.md`, `configs/proxy.example.yaml`, `deploy/demo/README.md`, `SECURITY.md`.
