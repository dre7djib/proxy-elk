# Spike SP-01/SP-02 — stack 8.19 + OpenLDAP + proxy transparent

Stack **jetable** du spike technique (voir [le plan du spike](../docs/Plan%20du%20spike%20%20proxy%20Elasticsearch%20et%20assistant%20IA%20dans%20Kibana.md)). Pas de tests, pas de belle architecture : le but est de lever un risque précis.

**Périmètre de SP-01** : Elasticsearch + Kibana 8.19 avec la sécurité activée, et un OpenLDAP peuplé d'utilisateurs de test. Le login natif testé ici est celui de l'utilisateur intégré `elastic`.

**Périmètre de SP-02** : un proxy Go minimal ([`proxy/`](proxy/)) s'intercale maintenant entre Kibana et Elasticsearch. C'est un **passe-plat transparent** (aucune authentification ni autorisation ajoutée) qui journalise chaque appel en JSON sur stdout, pour observer ce que Kibana envoie réellement à Elasticsearch. **OpenLDAP n'est toujours pas branché à Kibana** — ça viendra avec le login LDAP en SP-03.

## Démarrer

```sh
cd spike
cp .env.example .env   # ajuster les mots de passe si besoin
docker compose up -d
./scripts/verify.sh
```

`verify.sh` attend que les services répondent, puis vérifie :

- qu'Elasticsearch accepte `elastic` / `ELASTIC_PASSWORD` ;
- que le proxy est un passe-plat transparent (réponse identique en direct et via le proxy) et qu'une recherche authentifiée passe à travers lui (SP-02) ;
- que Kibana accepte ce même login via son API interne (`/internal/security/login`), preuve du critère de réussite « Kibana accepte un login natif » — maintenant à travers le proxy, puisque `ELASTICSEARCH_HOSTS` de Kibana pointe dessus ;
- qu'OpenLDAP contient alice, bob, carol et leurs groupes d'équipe ;
- qu'un bind LDAP avec un mauvais mot de passe est refusé.

Ouvrir ensuite http://127.0.0.1:5601 dans un navigateur et se connecter avec `elastic` / le mot de passe de `.env`, puis ouvrir Discover, pour une confirmation visuelle (aucune donnée chargée : attendu, SP-01 n'a créé aucun index).

## Accès

| Service | URL | Identifiants |
| --- | --- | --- |
| Elasticsearch (direct) | http://127.0.0.1:9200 | `elastic` / `ELASTIC_PASSWORD` (voir `.env`) |
| Proxy (SP-02, vers Elasticsearch) | http://127.0.0.1:9210 | mêmes identifiants, relayés tels quels |
| Kibana (passe par le proxy) | http://127.0.0.1:5601 | `elastic` / `ELASTIC_PASSWORD` |
| OpenLDAP | ldap://127.0.0.1:1389 | base `dc=example,dc=org`, admin `cn=admin,dc=example,dc=org` |

Utilisateurs LDAP de test (`ldap/01-bootstrap.ldif`), mots de passe en clair dans le LDIF (spike, pas un vrai secret) :

| uid | Mot de passe | Groupe | Rôle visé |
| --- | --- | --- | --- |
| alice | alicepass | `equipe-a-viewer` | viewer, équipe A |
| bob | bobpass | `equipe-a-editor` | editor, équipe A |
| carol | carolpass | `equipe-b-viewer` | viewer, équipe B |

Compte de lecture pour le search-then-bind (SP-03) : `uid=readonly,ou=people,dc=example,dc=org` / `readonlypass`.

## Journal du proxy (SP-02)

Chaque appel HTTP qui transite par le proxy produit une ligne JSON sur stdout (méthode, chemin, requête, statut, durée, et deux indicateurs `security` et `kibana_index`) :

```sh
docker compose logs -f proxy
docker compose logs proxy | grep '"security":true'     # appels à l'API de sécurité ES
docker compose logs proxy | grep '"kibana_index":true'  # appels touchant les index .kibana*
```

### Appels de sécurité observés

Relevé fait pendant un cycle complet connexion + ouverture de Discover (1 486 appels journalisés au total, dont 318 vers l'API de sécurité et 782 vers des index `.kibana*`) :

| Appel | Fréquence | Rôle probable |
| --- | --- | --- |
| `POST /_security/user/_has_privileges` | très fréquent (148) | Kibana vérifie en continu les droits de l'utilisateur courant avant d'afficher chaque fonctionnalité |
| `GET /_security/_authenticate` | très fréquent (145) | validation de session à chaque requête de l'UI (« qui suis-je ? ») |
| `GET /_security/profile/<uid>` | fréquent (16) | profil utilisateur (avatar, nom affiché) |
| `POST /_security/profile/_activate` | rare (2) | activation du profil utilisateur à la connexion |
| `DELETE /_security/api_key` | rare (5) | nettoyage de clés d'API internes à Kibana (ex. tâches Fleet/ML) |
| `GET /_security/api_key` | rare (1) | lecture de clés d'API internes |
| `GET /_security/privilege/kibana-.kibana` | rare (1) | privilèges applicatifs Kibana sur son propre index |

**Constat pour SP-03/F67** : `_has_privileges` et `_authenticate` sont de loin les appels les plus fréquents — toute identité usurpée via `run_as` devra répondre vite à ces deux endpoints, sans quoi l'UI de Kibana devient perceptiblement plus lente. Le reste du trafic (782 appels) touche uniquement des index `.kibana*` (sessions, saved objects, tâches internes, télémétrie) : c'est exactement le périmètre que F67 doit autoriser pour le compte de service `kibana_system`, rien de plus.

## Limites connues (acceptées pour un spike de 0,5 j)

- **Image OpenLDAP** : `osixia/openldap:1.5.0`, pas `bitnami/openldap`. Bitnami a retiré ses images gratuites de Docker Hub en 2025 (`docker.io/bitnami/openldap:2.6` introuvable au moment du spike, voir [bitnami/containers#83267](https://github.com/bitnami/containers/issues/83267)) ; `osixia/openldap` reste tirable et très utilisé, mais en maintenance réduite. À réévaluer avant J1 (construire sa propre image `slapd` au besoin).
- **Pas de TLS** entre Kibana et Elasticsearch, et LDAP en clair (pas LDAPS). Simplifie le proxy transparent de SP-02 ; à corriger avant toute vraie exploitation (F5, F68).
- **Un seul nœud** Elasticsearch, licence `basic` auto-générée.
- **Proxy sans authentification ni autorisation** : pur passe-plat qui journalise (SP-02). L'identité (run_as) arrive en SP-03, l'ACL au jalon J1 (F14).
- **Pas de rôles ES ni de spaces Kibana par équipe** : ça arrive en SP-04.
- **Pas d'index de données** : hors du critère de réussite de SP-01 et SP-02.

## Arrêter / nettoyer

```sh
docker compose down -v   # supprime aussi les volumes (données ES, Kibana, LDAP)
```
