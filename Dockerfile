FROM scratch
ADD jsonip /jsonip
EXPOSE 9008
ENTRYPOINT ["/jsonip"]
