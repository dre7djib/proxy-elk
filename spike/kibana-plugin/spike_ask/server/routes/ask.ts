import type { IRouter, Logger } from '@kbn/core/server';
import { schema } from '@kbn/config-schema';

interface AskRouteDeps {
  engineUrl: string;
  logger: Logger;
}

// Forme du jeton renvoyé par le proxy sur /_spike/identity-token (voir
// spike/proxy/main.go, mintIdentityTokenMiddleware). Le plugin ne déchiffre
// ni ne vérifie rien lui-même (F80) : il ne lit que le champ `token` pour le
// relayer au moteur, verbatim.
interface IdentityTokenResponse {
  token: string;
}

interface EngineWhoamiResponse {
  sub?: string;
  groups?: string[];
  aud?: string;
  exp?: number;
  [key: string]: unknown;
}

// registerAskRoute expose POST /api/spike_ask/ask : la seule route de ce
// plugin (SP-06). Elle matérialise la variante à tester en premier pour
// F78-F82 (voir le plan du spike, après l'étape 6) : obtenir le jeton court
// *via Elasticsearch*, avec la session de l'utilisateur courant, plutôt que
// par un canal séparé.
export function registerAskRoute(router: IRouter, deps: AskRouteDeps): void {
  router.post(
    {
      path: '/api/spike_ask/ask',
      validate: { body: schema.object({}, { unknowns: 'ignore' }) },
      // authRequired: true (valeur par défaut) : pas de session Kibana, pas
      // de route. C'est délibéré, alice doit être connectée pour ce spike.
    },
    async (context, request, response) => {
      const core = await context.core;

      // Point central du spike : asCurrentUser, PAS asInternalUser. Le
      // client ES scopé relaie l'Authorization/cookie d'origine de la
      // requête HTTP d'alice jusqu'au proxy (F2/F12 : ni le plugin ni ce
      // code ne voient jamais son mot de passe, seulement ce que Kibana a
      // déjà négocié pour sa session). Utiliser asInternalUser ici minterait
      // un jeton pour kibana_system, pas pour l'utilisateur : constat à
      // surveiller si jamais ce garde-fou est retiré par erreur.
      const esClient = core.elasticsearch.client.asCurrentUser;

      try {
        const tokenResponse = (await esClient.transport.request({
          method: 'POST',
          path: '/_spike/identity-token',
        })) as IdentityTokenResponse;

        if (!tokenResponse?.token) {
          deps.logger.warn('réponse du proxy sans champ token sur /_spike/identity-token');
          return response.customError({
            statusCode: 502,
            body: { message: 'le proxy n’a pas renvoyé de jeton' },
          });
        }

        // Relais sans modification (F80) : aucune clé lue, aucun claim
        // réécrit, le header Authorization du moteur ne contient rien
        // d'autre que ce que le proxy a signé.
        const engineResponse = await fetch(`${deps.engineUrl}/whoami`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${tokenResponse.token}` },
        });

        const engineBody = (await engineResponse
          .json()
          .catch(() => ({}))) as EngineWhoamiResponse;

        if (!engineResponse.ok) {
          return response.customError({
            statusCode: engineResponse.status,
            body: { message: 'moteur factice : jeton refusé', detail: engineBody },
          });
        }

        return response.ok({ body: engineBody });
      } catch (err) {
        deps.logger.error(`échec de l'appel /_spike/identity-token ou du moteur: ${err}`);
        return response.customError({
          statusCode: 502,
          body: { message: 'échec de la variante jeton via Elasticsearch', detail: `${err}` },
        });
      }
    }
  );
}
