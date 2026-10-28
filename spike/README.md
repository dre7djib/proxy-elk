# Spike SP-01 — stack 8.19 + OpenLDAP

Stack **jetable** du spike technique (voir [le plan du spike](../docs/Plan%20du%20spike%20%20proxy%20Elasticsearch%20et%20assistant%20IA%20dans%20Kibana.md)). Pas de tests, pas de belle architecture : le but est de lever un risque précis.

**Périmètre de SP-01** : Elasticsearch + Kibana 8.19 avec la sécurité activée, et un OpenLDAP peuplé d'utilisateurs de test. **OpenLDAP n'est pas encore branché à Kibana** — ça viendra avec le proxy en SP-02 et le login LDAP en SP-03. Le login natif testé ici est celui de l'utilisateur intégré `elastic`.

## Démarrer

```sh
cd spike
cp .env.example .env   # ajuster les mots de passe si besoin
docker compose up -d
./scripts/verify.sh
```

`verify.sh` attend que les trois services répondent, puis vérifie :

- qu'Elasticsearch accepte `elastic` / `ELASTIC_PASSWORD` ;
- que Kibana accepte ce même login via son API interne (`/internal/security/login`), preuve du critère de réussite « Kibana accepte un login natif » ;
- qu'OpenLDAP contient alice, bob, carol et leurs groupes d'équipe ;
- qu'un bind LDAP avec un mauvais mot de passe est refusé.

Ouvrir ensuite http://127.0.0.1:5601 dans un navigateur et se connecter avec `elastic` / le mot de passe de `.env`, pour une confirmation visuelle.

## Accès

| Service | URL | Identifiants |
| --- | --- | --- |
| Elasticsearch | http://127.0.0.1:9200 | `elastic` / `ELASTIC_PASSWORD` (voir `.env`) |
| Kibana | http://127.0.0.1:5601 | `elastic` / `ELASTIC_PASSWORD` |
| OpenLDAP | ldap://127.0.0.1:1389 | base `dc=example,dc=org`, admin `cn=admin,dc=example,dc=org` |

Utilisateurs LDAP de test (`ldap/01-bootstrap.ldif`), mots de passe en clair dans le LDIF (spike, pas un vrai secret) :

| uid | Mot de passe | Groupe | Rôle visé |
| --- | --- | --- | --- |
| alice | alicepass | `equipe-a-viewer` | viewer, équipe A |
| bob | bobpass | `equipe-a-editor` | editor, équipe A |
| carol | carolpass | `equipe-b-viewer` | viewer, équipe B |

Compte de lecture pour le search-then-bind (SP-03) : `uid=readonly,ou=people,dc=example,dc=org` / `readonlypass`.

## Limites connues (acceptées pour un spike de 0,5 j)

- **Image OpenLDAP** : `osixia/openldap:1.5.0`, pas `bitnami/openldap`. Bitnami a retiré ses images gratuites de Docker Hub en 2025 (`docker.io/bitnami/openldap:2.6` introuvable au moment du spike, voir [bitnami/containers#83267](https://github.com/bitnami/containers/issues/83267)) ; `osixia/openldap` reste tirable et très utilisé, mais en maintenance réduite. À réévaluer avant J1 (construire sa propre image `slapd` au besoin).
- **Pas de TLS** entre Kibana et Elasticsearch, et LDAP en clair (pas LDAPS). Simplifie le proxy transparent de SP-02 ; à corriger avant toute vraie exploitation (F5, F68).
- **Un seul nœud** Elasticsearch, licence `basic` auto-générée.
- **Pas de rôles ES ni de spaces Kibana par équipe** : ça arrive en SP-04.
- **Pas d'index de données** : hors du critère de réussite de SP-01.

## Arrêter / nettoyer

```sh
docker compose down -v   # supprime aussi les volumes (données ES, Kibana, LDAP)
```
