# Clés du jeton court (SP-06, F78-F82)

Paire de clés RSA 2048 **jetable**, générée pour ce spike (comme les mots de
passe en clair du LDIF, SP-01) — jamais une clé de production. Régénérée en
quelques secondes :

```sh
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

- [`private.pem`](private.pem) : clé privée. Montée **uniquement** sur le proxy (`JWT_PRIVATE_KEY_PATH`, [`../docker-compose.yml`](../docker-compose.yml)). Seul le proxy signe un jeton (F78) : ni le plugin Kibana ni le moteur n'y ont jamais accès (F80).
- [`public.pem`](public.pem) : clé publique. Montée **uniquement** sur le moteur factice (`JWT_PUBLIC_KEY_PATH`), qui vérifie la signature (F79) sans jamais pouvoir en émettre.
- [`wrong-private.pem`](wrong-private.pem) : **pas** utilisée par la stack. Sert uniquement de vecteur de test négatif (signature invalide) dans [`../scripts/verify-sp06.sh`](../scripts/verify-sp06.sh) : un jeton signé avec cette clé mais portant les bons claims doit être refusé par le moteur.

Pas de rotation dans ce spike (F81, une seule paire de clés) : c'est le périmètre de J2-03.
