FROM registry.opensource.zalan.do/stups/ubuntu:16.04-48

RUN apt-get update
RUN apt-get install -y wget vim
RUN wget -O /etc/apt/sources.list.d/scylla.list http://downloads.scylladb.com/deb/ubuntu/scylla-1.3-xenial.list
RUN apt-get update && apt-get install -y vim less scylla-server scylla-jmx scylla-tools --force-yes

COPY start-scylla /start-scylla
COPY scylladb_template.yaml /scylladb_template.yaml

ENV CASSANDRA_HOME /var/lib/cassandra

RUN rm -f /etc/scylla/scylla.yaml && chmod 0777 /etc/scylla
RUN mkdir -p /conf/ && touch /conf/cassandra-rackdc.properties

EXPOSE 10000 9042 9160 7000 7001

COPY scm-source.json /

CMD /start-scylla
