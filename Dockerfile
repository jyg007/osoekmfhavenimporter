# Use Alpine 3.21.3 as the base image
FROM debian:bookworm-slim

# Set a non-root user
#RUN addgroup -S ep11group && adduser -S ep11user -G ep11group
RUN groupadd -r ep11group && useradd -r -g ep11group ep11user

# Copy the required shared library
COPY  libep11.so.4.1.2 /usr/lib/s390x-linux-gnu/libep11.so.4

WORKDIR /ep11server

# Copy the Go server binary
COPY server /ep11server/server
COPY .env /ep11server
COPY key.pem /ep11server
COPY cert.pem /ep11server
RUN chown ep11user:ep11group /ep11server/*

# Set permissions
#RUN chown -R ep11user:ep11group /usr/local/bin/server /usr/lib64/libep11.so.4

# Switch to the non-root user
USER ep11user

# Expose port 9876
EXPOSE 9443

# Set the entrypoint to run the server
CMD ["/ep11server/server"]
