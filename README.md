# Proxy ELK

Proxy d'authentification et d'autorisation devant Elasticsearch auto-hébergé, avec un assistant IA intégré à Kibana par un plugin minimal. Open source (Apache-2.0).

> **Statut : conception.** Le projet est au stade du spike technique. Rien n'est encore utilisable en production.

## Pourquoi

Certaines fonctions de sécurité d'Elasticsearch (LDAP et Active Directory, SSO, audit) sont réservées aux offres payantes. Ce projet les apporte devant Elasticsearch sous forme de proxy externe, sans toucher au code d'Elastic ni à sa vérification de licence.

## Principes

- **Deny by default** : toute route ou action non reconnue est refusée.
- **Droits de l'utilisateur** : l'IA n'a jamais plus de droits que la personne connectée.
- **Lecture seule** pour tout ce que génère l'IA.
- **Transparence** : la requête générée est toujours visible et rejouable.
- **Kibana auto-hébergé uniquement** ; Elastic Cloud est hors périmètre.

## Feuille de route

| Jalon | Contenu | Livrable |
| --- | --- | --- |
| J1 | Authentification (OIDC, LDAP/AD), ACL, audit, secrets | Un proxy utilisable seul devant Elasticsearch |
| J2 | Assistant IA, plugin Kibana, équipes et spaces | La page « Ask » dans Kibana |
| J3 | Serveur MCP, analyse d'un log | Accès MCP et analyse IA d'un log précis |

Versions ciblées : Elasticsearch et Kibana 8.19. Une version 9.x sera ajoutée ensuite.

## Contribuer

Le projet n'accepte pas encore de contributions externes. Les règles (DCO ou CLA) seront définies avant la première publication.

## Sécurité

Pour signaler une faille, voir [SECURITY.md](SECURITY.md). Merci de ne pas ouvrir d'issue publique pour une vulnérabilité.

## Licence

[Apache-2.0](LICENSE).