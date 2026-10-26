# Testing instructions

Normally, the DSLAM lives in the game network as a separate entity, run by infra against the real
numbering plan (`meta/dslam/numbering-plan.yaml.template`).
That's fine in the final deployment, but we need to start it somewhere for local or CI setups.
Thus `game/` holds a stand-in for the game-network side: the DSLAM, a generator for a numbering plan
matching the local topology, and an nginx sidecar serving that plan to the checker the way k8s does in
the real deployment.

The steps to get things booted correctly:

1. Run `meta/build.sh` to build the toolchain and service binaries, and `meta/checker_build.sh` for the checker's copy of `zephyr.elf`.
2. Run `checker/build.sh` to build the checker images.
3. In `service`, run `docker compose build` to build the service images.
4. In `game`, run `docker compose up --detach --wait` to boot the DSLAM. Do this first: the router dials
   the DSLAM on startup, and the checker asks it for the numbering plan.
5. In `service`, run `docker compose up --detach --wait` to boot the service.
6. In `checker`, run `docker compose up --detach --wait` to boot the checker.
7. To run the full checker suite: `ENOCHECKER_FLAG_REGEX="ECSC\{[A-Za-z0-9-_]{32}\}" enochecker_test -p 8000 -n router-checker -N router`

Tear the three compose projects down in reverse order.
