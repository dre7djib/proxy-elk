# Politique de sécurité

## Versions supportées

Le projet n'a pas encore de version publiée. Dès la première version, seule la dernière version mineure recevra des correctifs de sécurité. Ce tableau sera mis à jour à chaque version.

| Version | Supportée |
| --- | --- |
| Pas encore de version publiée | - |

## Signaler une vulnérabilité

**N'ouvrez pas d'issue publique pour une faille de sécurité.**

Deux moyens de nous prévenir :

1. **Signalement privé GitHub** : onglet « Security » du dépôt, puis « Report a vulnerability ».
2. **E-mail** : ADRESSE-A-REMPLACER, avec pour objet « [SECURITY] » suivi d'un titre court.

Merci d'inclure :

- la version ou le commit concerné ;
- une description de la faille et de son impact ;
- les étapes pour la reproduire (idéalement une requête ou un scénario minimal) ;
- votre nom ou pseudonyme si vous souhaitez être cité dans le correctif.

## Ce que vous pouvez attendre

- Un accusé de réception sous 7 jours.
- Une première évaluation, puis des nouvelles régulières sur l'avancement.
- Une publication coordonnée : nous vous prévenons avant la divulgation et vous citons si vous le souhaitez.

Il s'agit d'un projet maintenu sur le temps libre de ses auteurs : ces délais sont un engagement de bonne foi, pas un contrat de service.

## Périmètre

Sont considérés comme des failles de sécurité, par exemple :

- le contournement de l'authentification ou de l'autorisation (ACL, alias, wildcards, index système) ;
- l'accès à Elasticsearch sans passer par le proxy ;
- l'injection (LDAP, requête ES|QL, prompt) qui permet de lire ou d'écrire des données non autorisées ;
- la fuite de secrets, de mots de passe ou de jetons dans les logs ou l'audit ;
- l'usurpation d'identité via les jetons (JWT, jetons personnels, en-têtes d'identité).

Les failles d'Elasticsearch, de Kibana ou d'un fournisseur de modèle sont à signaler directement à leurs éditeurs.