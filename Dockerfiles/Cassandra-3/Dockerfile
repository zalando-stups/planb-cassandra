FROM registry.opensource.zalan.do/stups/openjdk:8-39

MAINTAINER Zalando SE

# SSL Storage Port, Jolokia Agent, CQL Native
EXPOSE 7001 8778 9042

ENV CASSIE_VERSION=37x
ENV DEBIAN_FRONTEND=noninteractive

RUN echo "deb http://www.apache.org/dist/cassandra/debian ${CASSIE_VERSION} main deb-src" | tee -a /etc/apt/sources.list.d/apache.cassandra.list
RUN echo "deb http://www.apache.org/dist/cassandra/debian ${CASSIE_VERSION} main" | tee -a /etc/apt/sources.list.d/apache.cassandra.list
RUN gpg --keyserver pgp.mit.edu --recv-keys 0353B12C && gpg --export --armor 0353B12C | apt-key add -
RUN apt-get -y update && apt-get -y -o Dpkg::Options::='--force-confold' --fix-missing dist-upgrade
RUN apt-get -y install zip unzip vim less  # needed for the cqlsh issue workaround below
RUN apt-get -y update && apt-get -y install cassandra sysstat && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY TimeWindowCompactionStrategy-3.7.jar /usr/share/cassandra/lib/TimeWindowCompactionStrategy-3.7.jar

#
# Work around cqlsh issue with python-2.7.11+:
#   https://issues.apache.org/jira/browse/CASSANDRA-11850
#
# This can be removed once cassandra-2.1.16 or 3.0.9 is available.
#
WORKDIR /usr/share/cassandra/lib
RUN unzip cassandra-driver-internal-only-3.0.0-6af642d.zip cassandra-driver-3.0.0-6af642d/cassandra/cluster.py
RUN sed -i s/callback=partial/partial/g cassandra-driver-3.0.0-6af642d/cassandra/cluster.py
RUN zip -f cassandra-driver-internal-only-3.0.0-6af642d.zip cassandra-driver-3.0.0-6af642d/cassandra/cluster.py

RUN mkdir -p /opt/jolokia/

ADD http://search.maven.org/remotecontent?filepath=org/jolokia/jolokia-jvm/1.3.2/jolokia-jvm-1.3.2-agent.jar /opt/jolokia/jolokia-jvm-agent.jar
RUN chmod 744 /opt/jolokia/jolokia-jvm-agent.jar
RUN echo "f00fbaaf8c136d23f5f5ed9bacbc012a /opt/jolokia/jolokia-jvm-agent.jar" > /tmp/jolokia-jvm-agent.jar.md5
RUN md5sum --check /tmp/jolokia-jvm-agent.jar.md5
RUN rm -f /tmp/jolokia-jvm-agent.jar.md5

COPY cassandra_template.yaml /etc/cassandra/
COPY cassandra-env.sh /etc/cassandra/
COPY cassandra-env.sh-original /etc/cassandra/
COPY jvm.options /etc/cassandra/

# Override logging: STDOUT only
COPY logback.xml /etc/cassandra/

RUN rm -f /etc/cassandra/cassandra.yaml && chmod 0777 /etc/cassandra

COPY planb-cassandra.sh /usr/local/bin/

ENV HOME=/var/lib/cassandra
WORKDIR $HOME

CMD planb-cassandra.sh

COPY scm-source.json /
