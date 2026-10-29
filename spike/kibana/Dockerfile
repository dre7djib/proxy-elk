# Kibana 8.19.23 image + spike_ask plugin (SP-06), built in two stages
# as Elastic documents for 8.19 (external-plugin-development.html,
# plugin-tooling.html, k8s-kibana-plugins.html): the Kibana distributable
# no longer ships @kbn/optimizer, a plugin must be precompiled with the
# Kibana monorepo tooling before being installed with bin/kibana-plugin.
#
# RUNTIME FINDING (SP-06): this Dockerfile does build end to end
# in this spike's environment (Docker engine at ~4 GB RAM, see
# `docker info --format '{{.MemTotal}}'`) — this ticket's initial finding
# ("bootstrap too heavy, build impossible here") was wrong: the real
# blockers were three specific bugs, fixed below, not a resource
# limit:
#   1. kibana.json without `owner.name` (required by the manifest validator);
#   2. `plugin_helpers build` without `--kibana-version` attempts an
#      interactive prompt (inquirer) which fails for lack of a TTY in `docker build`;
#   3. the internal `buildWebpackPackages` task refuses to run as root
#      ("Kibana should not be run as root"), with no clean `--allow-root` flag
#      exposed by `plugin_helpers build` itself — fixed by building
#      as the non-root `node` user rather than looking for an extra
#      workaround.
# The full build (shallow clone + pnpm bootstrap + webpack build of the
# plugin + zip packaging + install into the official Kibana image)
# takes about 7 to 10 minutes depending on network speed. Details and end-to-end
# verification: spike/README.md#sp-06-minimal-kibana-plugin--short-lived-token-dummy-engine.
#
# To replay this build (the context is spike/, not spike/kibana/: the
# plugin lives in spike/kibana-plugin/):
#   DOCKER_BUILDKIT=1 docker build -f kibana/Dockerfile -t spike-kibana-ask .
# (from spike/), or simply `docker compose build kibana` /
# `docker compose up -d` which build this image automatically.

# ---- Stage 1: build the plugin inside a Kibana monorepo checkout ----
# Node version pinned to the exact patch (runtime finding, see
# spike/README.md#sp-06): Kibana 8.19.23 refuses to start its bootstrap
# on any version other than the one in its .node-version/.nvmrc, including
# a newer patch of the same minor (24.22.1 → rejected, requires
# 24.21.0 exactly) — not only a different major (20 → also rejected).
FROM node:24.21.0-bookworm AS plugin-builder
ARG KIBANA_TAG=v8.19.23
WORKDIR /build

RUN corepack enable \
    && git clone --depth 1 --branch ${KIBANA_TAG} https://github.com/elastic/kibana.git kibana

COPY kibana-plugin/spike_ask /build/kibana/plugins/spike_ask

# Runtime finding (SP-06): `pnpm kbn bootstrap --allow-root` is enough for
# the bootstrap itself, but the plugin's internal webpack build task
# (`buildWebpackPackages`, invoked by `plugin_helpers build`) re-checks
# "Kibana should not be run as root" on its own without exposing a clean
# `--allow-root` flag (rejected by the `plugin_helpers` option parser,
# "Unknown flag(s)"). Simpler and more correct than looking for an extra
# workaround: build as the non-root `node` user (already present in the
# official `node:*-bookworm` image), which needs no `--allow-root` anywhere.
RUN chown -R node:node /build
USER node
WORKDIR /build/kibana
# pnpm kbn bootstrap installs the whole monorepo's dependencies (required:
# the plugin's @kbn/core, @kbn/config-schema types come from here), then
# plugin-helpers build compiles only spike_ask into a distributable zip.
RUN corepack prepare pnpm@$(node -p "require('./package.json').engines.pnpm") --activate \
    && pnpm kbn bootstrap --no-validate \
    && cd plugins/spike_ask \
    && node ../../scripts/plugin_helpers build --kibana-version=$(node -p "require('../../package.json').version")

# ---- Stage 2: official Kibana image + plugin installed ----
FROM docker.elastic.co/kibana/kibana:8.19.23
COPY --from=plugin-builder /build/kibana/plugins/spike_ask/build/*.zip /tmp/spike_ask.zip
RUN /usr/share/kibana/bin/kibana-plugin install file:///tmp/spike_ask.zip \
    && /usr/share/kibana/bin/kibana --optimize
