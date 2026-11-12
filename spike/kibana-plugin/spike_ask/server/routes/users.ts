import type { IRouter, Logger } from '@kbn/core/server';
import { schema } from '@kbn/config-schema';
import { SPIKE_TEAM_ROLES, isSpikeTeamRole } from '../../common';

interface UsersRouteDeps {
  shadowPassword: string;
  logger: Logger;
}

const PROXY_RUNAS_ROLE = 'proxy_runas';

// Reserved / technical accounts that must never be created or overwritten
// by this spike UI (shadow users are for LDAP people only).
const RESERVED_USERNAMES = new Set([
  'elastic',
  'kibana_system',
  'proxy_service',
  'anonymous',
]);

interface RoleGetResponse {
  [name: string]: {
    cluster?: string[];
    indices?: unknown;
    run_as?: string[];
    applications?: unknown;
    metadata?: unknown;
  };
}

// registerUsersRoute exposes POST /api/spike_ask/users: create (or update)
// the Elasticsearch *native shadow* user for someone who already exists in
// LDAP, then extend proxy_runas.run_as so the proxy can impersonate them.
// The password is always the configured shadow secret — never taken from
// the UI, never the LDAP password.
export function registerUsersRoute(router: IRouter, deps: UsersRouteDeps): void {
  router.post(
    {
      path: '/api/spike_ask/users',
      validate: {
        body: schema.object({
          username: schema.string({ minLength: 1, maxLength: 64 }),
          fullName: schema.string({ minLength: 1, maxLength: 128 }),
          role: schema.string({ minLength: 1, maxLength: 64 }),
        }),
      },
    },
    async (context, request, response) => {
      if (!deps.shadowPassword) {
        deps.logger.error('spikeAsk.shadowPassword is empty: cannot create shadow users');
        return response.customError({
          statusCode: 500,
          body: { message: 'shadow password not configured (SPIKEASK_SHADOWPASSWORD)' },
        });
      }

      const { username, fullName, role } = request.body;
      const normalized = username.trim().toLowerCase();

      if (!/^[a-z][a-z0-9._-]{0,63}$/.test(normalized)) {
        return response.badRequest({
          body: {
            message:
              'username must be lowercase alphanumeric (start with a letter; . _ - allowed)',
          },
        });
      }
      if (RESERVED_USERNAMES.has(normalized)) {
        return response.badRequest({
          body: { message: `username "${normalized}" is reserved` },
        });
      }
      if (!isSpikeTeamRole(role)) {
        return response.badRequest({
          body: { message: `role must be one of: ${SPIKE_TEAM_ROLES.join(', ')}` },
        });
      }

      // asCurrentUser: only callers with manage security (e.g. elastic)
      // succeed; alice gets 403 from Elasticsearch. Never asInternalUser —
      // kibana_system must not mint shadow users on its own.
      const esClient = (await context.core).elasticsearch.client.asCurrentUser;

      try {
        await esClient.transport.request({
          method: 'PUT',
          path: `/_security/user/${encodeURIComponent(normalized)}`,
          body: {
            password: deps.shadowPassword,
            roles: [role],
            full_name: fullName.trim(),
          },
        });

        const roles = (await esClient.transport.request({
          method: 'GET',
          path: `/_security/role/${PROXY_RUNAS_ROLE}`,
        })) as RoleGetResponse;

        const current = roles[PROXY_RUNAS_ROLE];
        if (!current) {
          return response.customError({
            statusCode: 502,
            body: { message: `role ${PROXY_RUNAS_ROLE} missing; run es-bootstrap.sh` },
          });
        }

        const runAs = Array.isArray(current.run_as) ? [...current.run_as] : [];
        if (!runAs.includes(normalized)) {
          runAs.push(normalized);
          runAs.sort();
          await esClient.transport.request({
            method: 'PUT',
            path: `/_security/role/${PROXY_RUNAS_ROLE}`,
            body: {
              cluster: current.cluster ?? [],
              indices: current.indices ?? [],
              run_as: runAs,
            },
          });
        }

        // Never echo the shadow password.
        return response.ok({
          body: {
            username: normalized,
            fullName: fullName.trim(),
            role,
            runAs,
            created: true,
          },
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        const statusCode =
          err && typeof err === 'object' && 'statusCode' in err
            ? Number((err as { statusCode?: number }).statusCode)
            : undefined;
        deps.logger.error(`create shadow user failed: ${message}`);

        // Surface ES privilege denials as 403 so the UI can tell
        // "not allowed" apart from a plugin/config bug.
        if (
          statusCode === 403 ||
          /security_exception|unauthorized|status code 403/i.test(message)
        ) {
          return response.forbidden({
            body: { message: 'not allowed to create Elasticsearch users', detail: message },
          });
        }

        return response.customError({
          statusCode: 502,
          body: { message: 'failed to create shadow user', detail: message },
        });
      }
    }
  );
}
