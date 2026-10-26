ARG ZEPHYR_SOURCE=binary-prebuilt
ARG NETDEV_SOURCE=binary-prebuilt

# By default, use the prebuilt binaries
FROM scratch AS binary-prebuilt
COPY zephyr.elf base-disk.img netdev /

# (This needs a staging copy, per moby/moby #34482)
FROM ${ZEPHYR_SOURCE} AS zephyr-source
FROM ${NETDEV_SOURCE} AS netdev-source

# Debian trixie has a qemu version that is just barely too old for vfio-user support
FROM ubuntu:26.04@sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b

ADD --chmod=0755 --checksum=sha256:c125df9762b0c7233459087bb840c0e5dbfc4d9690ee227f1ed8994f4d51d2e0 \
    https://raw.githubusercontent.com/reproducible-containers/repro-sources-list.sh/v0.1.4/repro-sources-list.sh \
    /usr/local/bin/repro-sources-list.sh

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked --mount=type=cache,target=/var/lib/apt,sharing=locked \
    /usr/local/bin/repro-sources-list.sh && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --yes \
        qemu-system-misc && \
    rm -f /usr/local/bin/repro-sources-list.sh && \
    mkdir /router && \
    install --directory --owner nobody --group nogroup --mode 0755 /disk

WORKDIR /router/

COPY entrypoint.sh .

COPY --from=zephyr-source --chmod=444 /zephyr.elf .
COPY --from=zephyr-source --chmod=644 /base-disk.img .
COPY --from=netdev-source --chmod=555 /netdev /bin/netdev

CMD ["/router/entrypoint.sh"]
