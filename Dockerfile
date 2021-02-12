FROM ubuntu as APP

RUN mkdir /app 
WORKDIR /app

ADD dodas-IAMClientRec /usr/local/bin/dodas-IAMClientRec

ENTRYPOINT ["dodas-IAMClientRec"]