# Spike SP-01/SP-02/SP-03 — stack 8.19 + OpenLDAP + proxy + login LDAP (run_as)

Stack **jetable** du spike technique (voir [le plan du spike](../docs/Plan%20du%20spike%20%20proxy%20Elasticsearch%20et%20assistant%20IA%20dans%20Kibana.md)). Pas de tests, pas de belle architecture : le but est de lever un risque précis.

**Périmètre de SP-01** : Elasticsearch + Kibana 8.19 avec la sécurité activée, et un OpenLDAP peuplé d'utilisateurs de test. Le login natif testé ici est celui de l'utilisateur intégré `elastic`.

**Périmètre de SP-02** : un proxy Go minimal ([`proxy/`](proxy/)) s'intercale maintenant entre Kibana et Elasticsearch. C'est un **passe-plat transparent** (aucune authentification ni autorisation ajoutée) qui journalise chaque appel en JSON sur stdout, pour observer ce que Kibana envoie réellement à Elasticsearch.

**Périmètre de SP-03** : le proxy valide désormais le login LDAP (search-then-bind, F4) puis parle à Elasticsearch avec un compte de service en usurpant l'identité de l'utilisateur (`es-security-runas-user`, **piste A**). Alice se connecte à Kibana avec son mot de passe LDAP et apparaît avec sa propre identité et son rôle `viewer`. **Piste A validée par exécution réelle**, avec un correctif non prévu au départ : voir [Constat d'exécution — `_security/profile/_activate`](#constat-dexécution--securityprofile_activate-sp-03) plus bas.

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
- qu'OpenLDAP contient alice, bob, carol et leurs groupes d'équipe, et qu'un bind LDAP avec un mauvais mot de passe est refusé ;
- **(SP-03)** qu'Elasticsearch authentifie alice comme elle-même (`run_as`) avec son rôle `viewer`, et refuse un mauvais mot de passe LDAP sans jamais l'exposer à Elasticsearch ;
- **(SP-03)** qu'alice se connecte à **Kibana** avec son mot de passe LDAP, apparaît sous sa propre identité avec le rôle `viewer` (critère de réussite du ticket), qu'un mauvais mot de passe est refusé, et que le login natif `elastic` n'a pas régressé.

Ouvrir ensuite http://127.0.0.1:5601 dans un navigateur et se connecter avec `alice` / `alicepass` (ou `elastic` / le mot de passe de `.env`), puis ouvrir Discover, pour une confirmation visuelle (menu utilisateur = Alice Martin ; aucune donnée chargée : attendu, aucun index de données n'a été créé par le spike).

## Accès

| Service | URL | Identifiants |
| --- | --- | --- |
| Elasticsearch (direct) | http://127.0.0.1:9200 | `elastic` / `ELASTIC_PASSWORD` (voir `.env`) |
| Proxy (vers Elasticsearch) | http://127.0.0.1:9210 | `elastic` en passe-plat, ou **tout utilisateur LDAP** (alice/bob/carol) authentifié via le proxy (SP-03) |
| Kibana (passe par le proxy) | http://127.0.0.1:5601 | `elastic` / `ELASTIC_PASSWORD`, ou alice/bob/carol avec leur mot de passe LDAP (SP-03) |
| OpenLDAP | ldap://127.0.0.1:1389 | base `dc=example,dc=org`, admin `cn=admin,dc=example,dc=org` |

Utilisateurs LDAP de test (`ldap/01-bootstrap.ldif`), mots de passe en clair dans le LDIF (spike, pas un vrai secret) :

| uid | Mot de passe | Groupe | Rôle visé | Rôle natif ES (SP-03) |
| --- | --- | --- | --- | --- |
| alice | alicepass | `equipe-a-viewer` | viewer, équipe A | `viewer` |
| bob | bobpass | `equipe-a-editor` | editor, équipe A | `editor` |
| carol | carolpass | `equipe-b-viewer` | viewer, équipe B | `viewer` |

Le rôle natif ES n'isole pas encore par équipe (spaces, F70-F77) : ça arrive en SP-04. Côté Elasticsearch, alice/bob/carol ont un mot de passe natif qui n'est **jamais** celui ci-dessus (voir le constat SP-03 plus bas) : seul le mot de passe LDAP compte pour se connecter.

Compte de lecture pour le search-then-bind (F4, SP-03) : `cn=readonly,dc=example,dc=org` / `readonlypass` (créé par `LDAP_READONLY_USER=true`, pas `uid=readonly` comme un LDIF classique l'aurait créé).

## Journal du proxy (SP-02/SP-03)

Chaque appel HTTP qui transite par le proxy produit une ligne JSON sur stdout (méthode, chemin, requête, statut, durée, et deux indicateurs `security` et `kibana_index`, voir SP-02). Depuis SP-03, quatre champs en plus tracent l'authentification (jamais le mot de passe) :

- `auth_scheme` : `passthrough` (compte de service ou `elastic`), `ldap-runas` (utilisateur LDAP authentifié, requête relayée avec `run_as`), `ldap-profile-activate` (correctif `/_security/profile/_activate`, voir plus bas), `ldap-denied` (LDAP refusé), `basic-invalid`, ou `none` (pas d'en-tête).
- `user` : l'utilisateur authentifié (jamais le mot de passe).
- `run_as` : présent uniquement en `ldap-runas`, l'identité usurpée auprès d'Elasticsearch.
- `ldap_ms` : durée du search-then-bind (ou 0 si servi par le cache de 2 minutes, voir `LDAP_CACHE_TTL`).

```sh
docker compose logs -f proxy
docker compose logs proxy | grep '"security":true'       # appels à l'API de sécurité ES
docker compose logs proxy | grep '"kibana_index":true'    # appels touchant les index .kibana*
docker compose logs proxy | grep '"auth_scheme":"ldap-runas"'  # logins LDAP réussis (run_as)
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

**Constat pour SP-03/F67** : `_has_privileges` et `_authenticate` sont de loin les appels les plus fréquents — toute identité usurpée via `run_as` devra répondre vite à ces deux endpoints, sans quoi l'UI de Kibana devient perceptiblement plus lente. Le reste du trafic (782 appels) touche uniquement des index `.kibana*` (sessions, saved objects, tâches internes, télémétrie) : c'est exactement le périmètre que F67 doit autoriser pour le compte de service `kibana_system`, rien de plus. Le cache LDAP de 2 minutes (`LDAP_CACHE_TTL`) répond à ce constat : sans lui, chaque `_authenticate`/`_has_privileges` déclencherait un bind LDAP.

### Constat d'exécution — `_security/profile/_activate` (SP-03)

Pas prévu dans le plan initial du ticket, trouvé en faisant tourner le spike jusqu'au bout plutôt qu'en s'arrêtant à la théorie : le login d'alice échouait systématiquement en 401, alors que `GET /_security/_authenticate` avec `run_as` fonctionnait très bien.

Cause : juste après le login, Kibana appelle `POST /_security/profile/_activate` pour créer/activer le profil utilisateur (avatar, nom affiché). Cet appel est authentifié avec les identifiants de **kibana_system** (donc passe-plat pour le proxy), mais porte le mot de passe tapé par l'utilisateur dans le **corps JSON** (`{"grant_type":"password","username":"alice","password":"alicepass"}`), qu'Elasticsearch vérifie **lui-même** contre son realm natif — pas via le header `Authorization`, donc invisible à la logique `run_as` du proxy. Comme alice n'a pas de realm LDAP côté Elasticsearch (c'est tout le principe de la piste A), son vrai mot de passe LDAP ne correspond à rien côté ES, et la requête échoue avant même que Kibana puisse émettre une session.

Correctif implémenté dans [`proxy/main.go`](proxy/main.go) (`profileActivateMiddleware`) : pour ce point d'entrée précis, et seulement quand le grant vise un utilisateur LDAP (pas un compte de service), le proxy revérifie le mot de passe par LDAP (cache chaud dans la quasi-totalité des cas, puisque `_authenticate` vient de tourner juste avant), puis substitue dans le corps un secret partagé — `NATIVE_SHADOW_PASSWORD` — connu uniquement du proxy et du bootstrap Elasticsearch ([`scripts/es-bootstrap.sh`](scripts/es-bootstrap.sh), qui l'utilise comme mot de passe natif d'alice/bob/carol). Ce secret n'est **jamais** tapé par un utilisateur, jamais transmis à LDAP, jamais journalisé.

Ce correctif ne change rien au principe de la piste A (LDAP reste la seule source de vérité pour le mot de passe que l'utilisateur tape) ; il comble un angle mort précis de l'intégration Kibana + run_as, qui n'était pas visible dans le relevé des appels de SP-02 (2 appels sur 1 486, facile à manquer sans tester un vrai login bout en bout).

## Limites connues (acceptées pour un spike de 0,5 j)

- **Image OpenLDAP** : `osixia/openldap:1.5.0`, pas `bitnami/openldap`. Bitnami a retiré ses images gratuites de Docker Hub en 2025 (`docker.io/bitnami/openldap:2.6` introuvable au moment du spike, voir [bitnami/containers#83267](https://github.com/bitnami/containers/issues/83267)) ; `osixia/openldap` reste tirable et très utilisé, mais en maintenance réduite. À réévaluer avant J1 (construire sa propre image `slapd` au besoin).
- **Pas de TLS** entre Kibana et Elasticsearch, et LDAP en clair (pas LDAPS). Simplifie le proxy transparent de SP-02 ; à corriger avant toute vraie exploitation (F5, F68).
- **Un seul nœud** Elasticsearch, licence `basic` auto-générée.
- **Pas d'ACL** : tout utilisateur LDAP authentifié peut appeler n'importe quel index via le proxy, avec les droits de son rôle ES natif (`viewer`/`editor`, pas encore par équipe). L'ACL arrive au jalon J1 (F14).
- **Pas de rôles ES ni de spaces Kibana par équipe** : ça arrive en SP-04 (F70-F77). Alice, bob et carol ont aujourd'hui des rôles ES built-in (`viewer`/`editor`) communs, pas un rôle par équipe.
- **Pas de limitation des tentatives de connexion** (brute force, F8), ni de timeouts/pool de connexions LDAP dédiés (F10) : un seul bind à la fois, délai par défaut du client `go-ldap`.
- **`go.sum` non committé** ([`proxy/Dockerfile`](proxy/Dockerfile)) : `go mod tidy` résout `github.com/go-ldap/ldap/v3` à la construction de l'image, ce qui demande un accès réseau à `docker compose build` et n'est pas reproductible à l'octet près. Acceptable pour un spike, à corriger avant J1 (committer `go.sum`, vendoring ou miroir de modules).
- **Pas d'index de données** : hors du critère de réussite de SP-01, SP-02 et SP-03.

## Arrêter / nettoyer

```sh
docker compose down -v   # supprime aussi les volumes (données ES, Kibana, LDAP)
```
