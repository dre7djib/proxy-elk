# Image Kibana 8.19.23 + plugin spike_ask (SP-06), construite en deux temps
# comme le documente Elastic pour 8.19 (external-plugin-development.html,
# plugin-tooling.html, k8s-kibana-plugins.html) : le distributable Kibana
# n'embarque plus @kbn/optimizer, un plugin doit être précompilé avec l'outillage
# du monorepo Kibana avant d'être installé avec bin/kibana-plugin.
#
# CONSTAT D'EXÉCUTION (SP-06) : ce Dockerfile construit bien de bout en bout
# dans l'environnement de ce spike (moteur Docker à ~4 Go de RAM, voir
# `docker info --format '{{.MemTotal}}'`) — le constat initial de ce ticket
# ("bootstrap trop lourd, build impossible ici") était erroné : les vrais
# blocages étaient trois bugs précis, corrigés ci-dessous, pas une limite de
# ressources :
#   1. kibana.json sans `owner.name` (requis par le validateur de manifeste) ;
#   2. `plugin_helpers build` sans `--kibana-version` tente un prompt
#      interactif (inquirer) qui plante faute de TTY dans `docker build` ;
#   3. la tâche interne `buildWebpackPackages` refuse de tourner en root
#      ("Kibana should not be run as root"), sans flag `--allow-root` propre
#      exposé par `plugin_helpers build` lui-même — corrigé en construisant
#      comme l'utilisateur non-root `node` plutôt qu'en cherchant un
#      contournement supplémentaire.
# Le build complet (clone superficiel + bootstrap pnpm + build webpack du
# plugin + archivage en zip + installation dans l'image Kibana officielle)
# prend environ 7 à 10 minutes selon la vitesse réseau. Détail et vérification
# de bout en bout : spike/README.md#sp-06-plugin-kibana-minimal--jeton-court-moteur-factice.
#
# Pour rejouer ce build (le contexte est spike/, pas spike/kibana/ : le
# plugin vit dans spike/kibana-plugin/) :
#   DOCKER_BUILDKIT=1 docker build -f kibana/Dockerfile -t spike-kibana-ask .
# (depuis spike/), ou simplement `docker compose build kibana` /
# `docker compose up -d` qui construisent cette image automatiquement.

# ---- Stage 1 : build du plugin dans un checkout du monorepo Kibana ----
# Version de Node épinglée au patch exact (constat d'exécution, voir
# spike/README.md#sp-06) : Kibana 8.19.23 refuse de démarrer son bootstrap
# sur toute version différente de celle de son .node-version/.nvmrc, y
# compris un patch plus récent de la même mineure (24.22.1 → refusé, exige
# 24.21.0 pile) — pas seulement une majeure différente (20 → refusé aussi).
FROM node:24.21.0-bookworm AS plugin-builder
ARG KIBANA_TAG=v8.19.23
WORKDIR /build

RUN corepack enable \
    && git clone --depth 1 --branch ${KIBANA_TAG} https://github.com/elastic/kibana.git kibana

COPY kibana-plugin/spike_ask /build/kibana/plugins/spike_ask

# Constat d'exécution (SP-06) : `pnpm kbn bootstrap --allow-root` suffit pour
# le bootstrap lui-même, mais la tâche interne de build webpack du plugin
# (`buildWebpackPackages`, invoquée par `plugin_helpers build`) revérifie
# elle-même "Kibana should not be run as root" sans exposer de flag
# `--allow-root` propre (rejeté par le parser d'options de `plugin_helpers`,
# "Unknown flag(s)"). Plus simple et plus correct que de chercher un
# contournement supplémentaire : construire comme l'utilisateur non-root
# `node` (déjà présent dans l'image officielle `node:*-bookworm`), qui
# n'a besoin d'aucun `--allow-root` nulle part.
RUN chown -R node:node /build
USER node
WORKDIR /build/kibana
# pnpm kbn bootstrap installe les dépendances de tout le monorepo (nécessaire
# : les types @kbn/core, @kbn/config-schema du plugin viennent d'ici), puis
# plugin-helpers build compile uniquement spike_ask en zip distributable.
RUN corepack prepare pnpm@$(node -p "require('./package.json').engines.pnpm") --activate \
    && pnpm kbn bootstrap --no-validate \
    && cd plugins/spike_ask \
    && node ../../scripts/plugin_helpers build --kibana-version=$(node -p "require('../../package.json').version")

# ---- Stage 2 : image Kibana officielle + plugin installé ----
FROM docker.elastic.co/kibana/kibana:8.19.23
COPY --from=plugin-builder /build/kibana/plugins/spike_ask/build/*.zip /tmp/spike_ask.zip
RUN /usr/share/kibana/bin/kibana-plugin install file:///tmp/spike_ask.zip \
    && /usr/share/kibana/bin/kibana --optimize
