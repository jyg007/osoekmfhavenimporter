FROM gcr.io/distroless/cc-debian12

# Copy IBM EP11 library (if you ship it inside container)
COPY ./libep11.so.4.2.0 /lib/libep11.so.4
# Copy prebuilt Go binary
COPY ./ekmfimportserver /usr/local/bin/ekmfimportserver

# Run as non-root
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/ekmfimportserver"]
