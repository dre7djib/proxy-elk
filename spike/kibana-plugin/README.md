# `spike_ask` — plugin Kibana minimal du spike SP-06

Code source du plugin ([`spike_ask/`](spike_ask/)), à copier dans
`kibana/plugins/spike_ask/` d'un checkout du dépôt
[elastic/kibana](https://github.com/elastic/kibana) au tag `v8.19.23` (même
version que `STACK_VERSION` dans [`../.env.example`](../.env.example)), pour
être compilé par `pnpm build` depuis la racine du plugin et installé dans
l'image Kibana via `bin/kibana-plugin install`. Voir
[`../kibana/Dockerfile`](../kibana/Dockerfile) pour l'automatisation complète
et le constat d'exécution sur la faisabilité de ce build dans l'environnement
du spike.

Périmètre volontairement minimal (SP-06, F39-F41 + F78-F82) :

- une application « Spike Ask » dans le menu de gauche ([`public/`](spike_ask/public/)), un bouton, un `<pre>` qui affiche la réponse du moteur ;
- une route serveur unique, `POST /api/spike_ask/ask` ([`server/routes/ask.ts`](spike_ask/server/routes/ask.ts)), qui :
  1. appelle `POST /_spike/identity-token` sur Elasticsearch via `context.core.elasticsearch.client.asCurrentUser` (jamais `asInternalUser` : c'est le point qui fait que le jeton minté par le proxy porte l'identité d'alice, pas celle de `kibana_system`) — c'est la variante « jeton demandé via ES avec la session de l'utilisateur » du plan du spike ;
  2. relaie le jeton reçu, sans le lire ni le modifier (F80), au moteur factice (`POST {engineUrl}/whoami`, `Authorization: Bearer <jeton>`) ;
  3. renvoie à l'UI la réponse du moteur (identité vérifiée) ou l'erreur.

Pas de question en langage naturel, pas de lien Discover, pas de dépendance à `data`/`discover` : ça reste le périmètre de J2-05/J2-06. Le plugin ne détient aucune clé de signature (F80) : il n'y a ni clé privée ni clé publique dans ce dossier.
