FROM ubuntu as APP

RUN apt-get update && apt-get install -y ca-certificates
RUN mkdir /app 
WORKDIR /app

ADD dodas-IAMClientRec /usr/local/bin/dodas-IAMClientRec

ENTRYPOINT ["dodas-IAMClientRec"]
