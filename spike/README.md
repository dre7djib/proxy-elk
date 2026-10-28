# Spike SP-01 à SP-05 — stack 8.19 + OpenLDAP + proxy + login LDAP (run_as) + rôles/spaces par équipe + ES|QL

Stack **jetable** du spike technique (voir [le plan du spike](../docs/Plan%20du%20spike%20%20proxy%20Elasticsearch%20et%20assistant%20IA%20dans%20Kibana.md)). Pas de tests, pas de belle architecture : le but est de lever un risque précis.

**Périmètre de SP-01** : Elasticsearch + Kibana 8.19 avec la sécurité activée, et un OpenLDAP peuplé d'utilisateurs de test. Le login natif testé ici est celui de l'utilisateur intégré `elastic`.

**Périmètre de SP-02** : un proxy Go minimal ([`proxy/`](proxy/)) s'intercale maintenant entre Kibana et Elasticsearch. C'est un **passe-plat transparent** (aucune authentification ni autorisation ajoutée) qui journalise chaque appel en JSON sur stdout, pour observer ce que Kibana envoie réellement à Elasticsearch.

**Périmètre de SP-03** : le proxy valide désormais le login LDAP (search-then-bind, F4) puis parle à Elasticsearch avec un compte de service en usurpant l'identité de l'utilisateur (`es-security-runas-user`, **piste A**). Alice se connecte à Kibana avec son mot de passe LDAP et apparaît avec sa propre identité et son rôle. **Piste A validée par exécution réelle**, avec un correctif non prévu au départ : voir [Constat d'exécution — `_security/profile/_activate`](#constat-dexécution--securityprofile_activate-sp-03) plus bas.

**Périmètre de SP-04** : les rôles ES built-in `viewer`/`editor` de SP-03 (accès à tous les spaces) sont remplacés par un rôle par couple équipe/niveau (`equipe_a_viewer`, `equipe_a_editor`, `equipe_b_viewer`) et un space Kibana par équipe (`equipe-a`, `equipe-b`). Nouveau service `kibana-setup` ([`scripts/kibana-bootstrap.sh`](scripts/kibana-bootstrap.sh)), lancé après que Kibana soit joignable, qui crée les spaces et complète les rôles via l'API rôles de Kibana (privilèges `elasticsearch` + `kibana`, pas l'API rôles d'Elasticsearch directement). **Critère de réussite atteint par exécution réelle** : alice lit seulement le space et les données de l'équipe A, bob modifie un dashboard de l'équipe A, carol ne voit rien de l'équipe A — vérifié via [`scripts/verify.sh`](scripts/verify.sh). Détail dans [Rôles ES et spaces Kibana par équipe](#rôles-es-et-spaces-kibana-par-équipe-sp-04) plus bas.

**Périmètre de SP-05** : `FROM`, `LOOKUP JOIN` et `ENRICH` testés via le proxy sur 8.19.23, en `elastic` puis en `alice` (chemin LDAP → `run_as`). Les trois fonctionnent. Constat majeur : l'ACL native d'Elasticsearch protège l'index **cible** d'un `LOOKUP JOIN` tout comme un `FROM`, mais **pas** celui d'une policy `ENRICH` (seulement un privilège cluster global `monitor_enrich`/`manage_enrich`) — fuite inter-équipe démontrée. Détail dans [SP-05 FROM LOOKUP JOIN et ENRICH via le proxy](#sp-05-from-lookup-join-et-enrich-via-le-proxy) plus bas.

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
- **(SP-03)** qu'Elasticsearch authentifie alice comme elle-même (`run_as`) avec son rôle, et refuse un mauvais mot de passe LDAP sans jamais l'exposer à Elasticsearch ;
- **(SP-03)** qu'alice se connecte à **Kibana** avec son mot de passe LDAP et apparaît sous sa propre identité, qu'un mauvais mot de passe est refusé, et que le login natif `elastic` n'a pas régressé ;
- **(SP-04)** que le service `kibana-setup` s'est terminé avec succès, qu'alice ne voit que le space `equipe-a` et ses données, que bob peut modifier un dashboard de l'équipe A, et que carol ne voit ni le space ni les données de l'équipe A (critère de réussite du ticket).

Ouvrir ensuite http://127.0.0.1:5601 dans un navigateur et se connecter avec `alice` / `alicepass`, `bob` / `bobpass` ou `carol` / `carolpass` (ou `elastic` / le mot de passe de `.env`), pour une confirmation visuelle : le space switcher ne propose que `equipe-a` à alice/bob et `equipe-b` à carol, et le dashboard « Dashboard equipe A (SP-04) » n'est visible/modifiable que dans le space `equipe-a`.

## Accès

| Service | URL | Identifiants |
| --- | --- | --- |
| Elasticsearch (direct) | http://127.0.0.1:9200 | `elastic` / `ELASTIC_PASSWORD` (voir `.env`) |
| Proxy (vers Elasticsearch) | http://127.0.0.1:9210 | `elastic` en passe-plat, ou **tout utilisateur LDAP** (alice/bob/carol) authentifié via le proxy (SP-03) |
| Kibana (passe par le proxy) | http://127.0.0.1:5601 | `elastic` / `ELASTIC_PASSWORD`, ou alice/bob/carol avec leur mot de passe LDAP (SP-03) |
| OpenLDAP | ldap://127.0.0.1:1389 | base `dc=example,dc=org`, admin `cn=admin,dc=example,dc=org` |

Utilisateurs LDAP de test (`ldap/01-bootstrap.ldif`), mots de passe en clair dans le LDIF (spike, pas un vrai secret) :

| uid | Mot de passe | Groupe LDAP | Rôle natif ES (SP-04) | Space Kibana |
| --- | --- | --- | --- | --- |
| alice | alicepass | `equipe-a-viewer` | `equipe_a_viewer` (lecture) | `equipe-a` seulement |
| bob | bobpass | `equipe-a-editor` | `equipe_a_editor` (lecture+écriture Kibana) | `equipe-a` seulement |
| carol | carolpass | `equipe-b-viewer` | `equipe_b_viewer` (lecture) | `equipe-b` seulement |

Le groupe LDAP n'est pas encore mappé automatiquement vers le rôle ES (mapping groupes → équipe/niveau, F72) : l'affectation reste statique dans [`scripts/es-bootstrap.sh`](scripts/es-bootstrap.sh), comme en SP-03 ; ça arrivera avec la config YAML de J2-01. Côté Elasticsearch, alice/bob/carol ont un mot de passe natif qui n'est **jamais** celui ci-dessus (voir le constat SP-03 plus bas) : seul le mot de passe LDAP compte pour se connecter.

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

## Rôles ES et spaces Kibana par équipe (SP-04)

Objectif du ticket : un rôle Elasticsearch et un space Kibana par équipe, pour qu'alice (équipe A, viewer) ne lise que les données et le space de son équipe, que bob (équipe A, editor) puisse modifier un dashboard de son équipe, et que carol (équipe B, viewer) ne voie rien de l'équipe A.

### Pourquoi deux scripts de bootstrap

Les privilèges Kibana (`base: read`/`all`, `spaces`) doivent être posés via l'**API rôles de Kibana** (`PUT /api/security/role/{name}`), pas directement via `PUT /_security/role` d'Elasticsearch : Kibana enregistre lui-même ses privilèges applicatifs (`kibana-.kibana`) à son démarrage, et les spaces n'existent tout simplement pas avant que Kibana ne soit démarré. Le service `setup` existant (SP-01/SP-03) se termine **avant** Kibana (il ne dépend que d'Elasticsearch) : impossible d'y créer les spaces ou les privilèges Kibana.

Deux scripts, dans l'ordre :

1. [`scripts/es-bootstrap.sh`](scripts/es-bootstrap.sh) (service `setup`, inchangé dans son principe) : crée trois rôles ES **stub** (`equipe_a_viewer`, `equipe_a_editor`, `equipe_b_viewer`), sans aucun privilège, juste pour qu'alice/bob/carol puissent leur être assignés sans erreur côté Elasticsearch. Remplace les rôles built-in `viewer`/`editor` de SP-03, qui donnaient accès à tous les spaces.
2. [`scripts/kibana-bootstrap.sh`](scripts/kibana-bootstrap.sh) (nouveau service `kibana-setup`, démarre seulement une fois Kibana `healthy`) : crée les spaces `equipe-a` et `equipe-b` (`POST`/`PUT /api/spaces/space`), puis réécrit entièrement les trois rôles stub via l'API rôles de Kibana (`elasticsearch.indices` + `kibana.base`/`spaces`), indexe un document de test dans `equipe-a-sample` et `equipe-b-sample` (directement sur Elasticsearch, pour vérifier l'isolation des *données* et pas seulement des objets Kibana), et crée un dashboard minimal dans le space `equipe-a` (`spike-dashboard-equipe-a`).

Entre la fin de `setup` et la fin de `kibana-setup`, alice/bob/carol ont un rôle sans aucun privilège : ils peuvent se connecter mais ne voient aucun space. Fenêtre courte, jugée acceptable pour un spike.

Définition des rôles complets (posée par `kibana-bootstrap.sh`) :

| Rôle | Index ES (`read`) | Space Kibana | Base Kibana |
| --- | --- | --- | --- |
| `equipe_a_viewer` | `equipe-a-*` | `equipe-a` | `read` |
| `equipe_a_editor` | `equipe-a-*` | `equipe-a` | `all` |
| `equipe_b_viewer` | `equipe-b-*` | `equipe-b` | `read` |

Editor et viewer de l'équipe A ont les **mêmes** privilèges d'index (lecture) : la différence porte sur les objets Kibana du space (dashboards, etc.), pas sur les données elles-mêmes — c'est le périmètre du critère de réussite (« bob peut modifier un dashboard de A »), pas un droit d'écriture sur les données.

### Constat d'exécution — Dev Tools déjà fermé par `base: read` (SP-04)

Avant d'implémenter, le risque identifié était qu'un rôle `base: ["read"]` laisse Dev Tools visible pour un viewer (les sous-privilèges par sous-fonctionnalité sont une fonction payante, donc pas de moyen fin de le masquer). **Testé réellement** (`POST /api/console/proxy` avec la session d'alice) : Kibana 8.19 refuse déjà cet appel en 403 (« this action is granted by the Kibana privileges [console] ») avec le seul `base: read`, sans configuration `feature` supplémentaire. Pas besoin de personnaliser les privilèges par fonctionnalité pour ce cas précis ; utile aussi pour SP-07 (licence Basic : la restriction Dev Tools ne vient pas d'un palier payant, elle est déjà dans le comportement de base).

### Vérification

[`scripts/verify.sh`](scripts/verify.sh) étend la matrice SP-01 à SP-03 avec, une fois le service `kibana-setup` terminé (vérifié via `docker compose ps --format '{{.State}}' kibana-setup`) :

- alice : `GET /api/spaces/space` contient `equipe-a` et pas `equipe-b` ; lecture du dashboard de A (200) ; tentative d'écriture sur ce même dashboard refusée (403) ; Dev Tools refusé (403) ; recherche sur `equipe-a-sample` via le proxy (200) et sur `equipe-b-sample` refusée (403).
- bob : connexion Kibana réussie ; écriture réussie (200) sur le dashboard de A.
- carol : `GET /api/spaces/space` contient seulement `equipe-b` ; accès direct au space `equipe-a` et à son dashboard refusés (403 chacun) ; recherche sur `equipe-a-sample` via le proxy refusée (403), sur `equipe-b-sample` réussie (200).

Exécuté réellement (pas seulement en théorie) : `docker compose up -d` puis `./scripts/verify.sh`, deux fois de suite (`setup`/`kibana-setup` relancés entre les deux) pour vérifier que les deux scripts de bootstrap restent idempotents sans erreur.

Si un cas de cette matrice échoue, ne pas commencer par regarder le proxy : d'abord `GET /_security/_authenticate` via le proxy (le rôle custom est-il présent ?), puis `POST /_security/user/_has_privileges`, puis le même appel Kibana en session `elastic` pour voir si l'objet existe. Un 401 inattendu dans le journal du proxy indique un problème côté `run_as` ; un 403 côté Kibana ou ES indique un problème de définition de rôle ou de space, pas le proxy.

### Hors périmètre de SP-04 (prévu en J2)

Pas de configuration YAML source unique, pas de synchronisation générique/idempotente au sens de F74-F77 (l'idempotence testée ici est manuelle, pas garantie par construction), pas de niveau `admin`, pas de mapping automatique des groupes LDAP vers équipe/niveau (F72), pas de détection de divergence (F76), pas de mode simulation (F77). L'affectation alice/bob/carol → rôle reste statique dans `es-bootstrap.sh`, comme en SP-03. Ça arrive en J2-01 (config YAML) et J2-02 (synchro idempotente).

## SP-05 FROM LOOKUP JOIN et ENRICH via le proxy

Objectif du ticket : savoir quelles commandes ES|QL référencent d'autres index en 8.19, et la version minimale d'Elasticsearch à retenir pour F27 (vérification des index lus par une requête avant exécution, garde-fou de l'assistant IA).

### Pourquoi les index de test suivent le pattern `equipe-a-*`/`equipe-b-*`

Le plan initial du ticket supposait encore le rôle built-in `viewer` d'alice (accès large à tous les index). Entre-temps, SP-04 l'a remplacé par un rôle restreint au pattern `equipe-a-*` (voir plus haut). Avec des index nommés `sp05-*` comme prévu au plan, alice n'aurait pu en lire aucun : le test via son identité LDAP n'aurait rien démontré sur ES|QL lui-même.

[`scripts/esql-seed.sh`](scripts/esql-seed.sh) crée donc deux jeux d'index, un par équipe :

| Usage | Équipe A (lisible par alice) | Équipe B (pas lisible par alice) |
| --- | --- | --- |
| `FROM` | `equipe-a-sp05-logs` | `equipe-b-sp05-logs` (témoin négatif) |
| `LOOKUP JOIN` (`index.mode: lookup`) | `equipe-a-sp05-hosts` | `equipe-b-sp05-hosts` |
| `ENRICH` (index source + policy) | `equipe-a-sp05-owners` / `sp05-owners-a-policy` | `equipe-b-sp05-owners` / `sp05-owners-b-policy` |

Ce choix permet de répondre à la vraie question de F27 : est-ce qu'Elasticsearch isole nativement l'index **cible** d'un `LOOKUP JOIN` ou la policy d'un `ENRICH`, au même titre que le `FROM` ? Sans ce test croisé, on n'aurait vérifié que la capacité brute des commandes (avec `elastic`), pas leur comportement de sécurité réel.

### Constat d'exécution — LOOKUP JOIN exige un champ `keyword`

Première tentative refusée en 400 pour **tout le monde**, y compris `elastic` (donc sans rapport avec l'ACL) : `verification_exception`, *"JOIN with right field [host] of type [TEXT] is not supported"*. Le champ de jointure `host`, laissé en mapping dynamique, était du `text`. Corrigé en mappant explicitement `host` (et `owner`) en `keyword` dans `esql-seed.sh`.

### Exécuter

```sh
./scripts/esql-seed.sh     # crée les index et policies ci-dessus (relançable)
./scripts/verify-esql.sh   # joue FROM/LOOKUP JOIN/ENRICH en elastic puis en alice
```

`verify-esql.sh` n'est volontairement pas un gate pass/fail comme `verify.sh` : certains résultats attendus sont des refus (403), et deux cas sont marqués « constat ouvert » dans la sortie — c'est la vraie question du spike, pas une régression si le résultat n'est pas celui espéré.

### Résultats

| Commande | Référence un index dans le texte ? | ACL native ES sur la cible | Version minimale 8.x utile |
| --- | --- | --- | --- |
| `FROM` | oui (patterns, listes, nom quoté) | oui : liste explicite avec un index non autorisé → `403` ; wildcard élargi (`equipe-*-sp05-logs`) → filtré silencieusement aux index autorisés d'alice, sans erreur et sans fuite constatée | GA depuis 8.14 |
| `LOOKUP JOIN idx ON champ` | oui, nom d'index exact obligatoire | **oui** : alice refusée (400, « Unknown index ») sur `LOOKUP JOIN equipe-b-sp05-hosts ON host`, alors qu'elastic réussit la même requête | GA en 8.19 (preview en 8.18) |
| `ENRICH policy` | **non**, seulement un nom de policy | **non**, voir constat majeur ci-dessous | GA depuis les débuts d'ES\|QL, mais insuffisant seul pour F27 |

### Constat d'exécution majeur — ENRICH n'est pas protégé par index source

`ENRICH` nécessite uniquement le privilège **cluster** `monitor_enrich`/`manage_enrich` — confirmé par le message d'erreur d'Elasticsearch quand alice (rôle `equipe_a_viewer`, sans ce privilège) tente `ENRICH sp05-owners-a-policy` :

```
action [cluster:monitor/xpack/enrich/esql/resolve_policy] is unauthorized for user [proxy_service]
run as [alice] with effective roles [equipe_a_viewer], this action is granted by the cluster
privileges [cross_cluster_search,monitor_enrich,manage_enrich,monitor,manage,all]
```

Sans ce privilège, `ENRICH` est refusé en bloc, **même pour la policy de sa propre équipe** (403 sur `sp05-owners-a-policy` aussi). Mais le privilège est **cluster-wide**, pas par policy ni par index source : pour tester ce qu'il se passe une fois accordé, un rôle temporaire a été créé et attaché à alice le temps du test, puis retiré :

```sh
curl -u "elastic:${ELASTIC_PASSWORD}" -X PUT http://127.0.0.1:9200/_security/role/sp05_monitor_enrich_test \
  -H 'Content-Type: application/json' \
  -d '{"cluster":["monitor_enrich"],"indices":[{"names":["equipe-a-*"],"privileges":["read","view_index_metadata"]}]}'
curl -u "elastic:${ELASTIC_PASSWORD}" -X PUT http://127.0.0.1:9200/_security/user/alice \
  -H 'Content-Type: application/json' \
  -d '{"roles":["equipe_a_viewer","sp05_monitor_enrich_test"],"full_name":"Alice Martin"}'
```

Résultat : `FROM equipe-a-sp05-logs | ENRICH sp05-owners-b-policy ON host`, exécuté par alice via le proxy, a renvoyé `"owner": "equipe-b-secret"` — la valeur de l'index source de l'équipe **B**, alors qu'alice n'a aucun privilège de lecture sur `equipe-b-sp05-owners` ni `equipe-b-*`. **Fuite inter-équipe confirmée.** Rôle et affectation retirés immédiatement après le test.

**Conséquence directe pour F27** : `FROM` et `LOOKUP JOIN` sont déjà protégés par l'ACL native d'Elasticsearch (le nom de l'index cible est toujours explicite dans le texte de la requête) ; un parseur qui extrait ces noms (pour l'audit F49 et le refus fail-closed) suffit, sans contrôle d'autorisation supplémentaire côté proxy. `ENRICH` demande un traitement spécifique : le proxy doit résoudre `GET /_enrich/policy/<nom>` pour retrouver l'index source avant d'autoriser l'exécution, et refuser si la policy est inconnue ou si l'index source sort du périmètre de l'utilisateur (fail-closed, F38) — sans quoi accorder `monitor_enrich` à une équipe pour qu'elle utilise `ENRICH` l'expose de fait aux policies de toutes les autres équipes.

**Version minimale d'Elasticsearch retenue** : **8.19** si `LOOKUP JOIN` doit être couvert par F27 en production (GA à cette version, alignée avec le choix déjà fait pour Kibana 8.19). 8.14 suffirait pour `FROM` + `ENRICH` seuls. Pas de `FORK` en 8.19 : seules ces trois commandes lisent d'autres données.

### Hors périmètre de SP-05

Parser F27 (extraction des index, résolution des policies ENRICH, fail-closed), toute modification du proxy (`/_query` traverse déjà le passe-plat existant sans changement, visible dans `docker compose logs proxy | grep '"path":"/_query"'`), et le cluster distant (CCS) — la syntaxe `cluster:index` de `FROM` est documentée mais pas testée avec un vrai cluster remote. Détail du ticket dans [SP-05](../docs/Tickets%20Proxy%20Elasticsearch/SP-05%20ES-QL%20-%20FROM%2C%20LOOKUP%20JOIN%2C%20ENRICH%20via%20proxy.md).

## Limites connues (acceptées pour un spike de 0,5 j)

- **Image OpenLDAP** : `osixia/openldap:1.5.0`, pas `bitnami/openldap`. Bitnami a retiré ses images gratuites de Docker Hub en 2025 (`docker.io/bitnami/openldap:2.6` introuvable au moment du spike, voir [bitnami/containers#83267](https://github.com/bitnami/containers/issues/83267)) ; `osixia/openldap` reste tirable et très utilisé, mais en maintenance réduite. À réévaluer avant J1 (construire sa propre image `slapd` au besoin).
- **Pas de TLS** entre Kibana et Elasticsearch, et LDAP en clair (pas LDAPS). Simplifie le proxy transparent de SP-02 ; à corriger avant toute vraie exploitation (F5, F68).
- **Un seul nœud** Elasticsearch, licence `basic` auto-générée.
- **Pas d'ACL** : tout utilisateur LDAP authentifié peut appeler n'importe quel index via le proxy, avec les droits de son rôle ES (par équipe depuis SP-04, mais statique et non dérivé d'une politique déclarative). L'ACL arrive au jalon J1 (F14).
- **Pas de YAML ni de synchro générique pour les rôles/spaces** : depuis SP-04, les rôles et spaces par équipe existent (F70-F75 validés par exécution réelle), mais l'affectation utilisateur → rôle reste statique dans `es-bootstrap.sh` (pas de mapping groupes LDAP → équipe/niveau, F72), et il n'y a ni source YAML unique, ni détection de divergence (F76), ni mode simulation (F77). Ça arrive en J2-01/J2-02.
- **Pas de limitation des tentatives de connexion** (brute force, F8), ni de timeouts/pool de connexions LDAP dédiés (F10) : un seul bind à la fois, délai par défaut du client `go-ldap`.
- **`go.sum` non committé** ([`proxy/Dockerfile`](proxy/Dockerfile)) : `go mod tidy` résout `github.com/go-ldap/ldap/v3` à la construction de l'image, ce qui demande un accès réseau à `docker compose build` et n'est pas reproductible à l'octet près. Acceptable pour un spike, à corriger avant J1 (committer `go.sum`, vendoring ou miroir de modules).
- **Index de données minimal** : `equipe-a-sample`/`equipe-b-sample` n'ont qu'un document de test chacun (SP-04), juste pour vérifier l'isolation par équipe ; pas un vrai jeu de données.
- **ENRICH non protégé par index source (SP-05)** : confirmé par exécution réelle, voir [SP-05](#sp-05-from-lookup-join-et-enrich-via-le-proxy). F27 doit résoudre la policy vers son index source avant d'autoriser l'exécution ; ni le proxy actuel ni Elasticsearch ne le font nativement.
- **Index de test SP-05 non nettoyés par `docker compose down -v`** : `equipe-*-sp05-*` et les policies `sp05-owners-*-policy` sont créés par [`scripts/esql-seed.sh`](scripts/esql-seed.sh) directement sur Elasticsearch ; ils disparaissent avec le volume `esdata` comme le reste, mais ne sont pas recréés automatiquement par `docker compose up` (relancer `esql-seed.sh` à la main si besoin).

## Arrêter / nettoyer

```sh
docker compose down -v   # supprime aussi les volumes (données ES, Kibana, LDAP)
```
