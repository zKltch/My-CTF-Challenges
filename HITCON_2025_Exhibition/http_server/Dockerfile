FROM fedora@sha256:c3643bda846169b342b400d4bbd1cb7022a7037e108b403a97305d1cb1644bcd

WORKDIR /app

COPY ./share /app
RUN chmod +x /app/*

CMD ["/app/server"]
