FROM registry.opensource.zalan.do/stups/openjdk:8-39

MAINTAINER Zalando SE

# SSL Storage Port, Jolokia Agent, CQL Native
EXPOSE 7001 8778 9042

ENV CASSIE_VERSION=2.1.14

ENV DEBIAN_FRONTEND=noninteractive
RUN echo "deb http://debian.datastax.com/community stable main" | tee -a /etc/apt/sources.list.d/datastax.community.list
RUN curl -sL https://debian.datastax.com/debian/repo_key | apt-key add -
RUN apt-get -y update && apt-get -y -o Dpkg::Options::='--force-confold' --fix-missing dist-upgrade
RUN apt-get -y install zip unzip less vim # needed for the cqlsh issue workaround below
RUN apt-get -y install cassandra=$CASSIE_VERSION cassandra-tools=$CASSIE_VERSION sysstat && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#
# Work around cqlsh issue with python-2.7.11+:
#   https://issues.apache.org/jira/browse/CASSANDRA-11850
#
# This can be removed once cassandra-2.1.16 is available.
#
WORKDIR /usr/share/cassandra/lib
RUN unzip cassandra-driver-internal-only-2.7.2.zip cassandra-driver-2.7.2/cassandra/cluster.py
RUN sed -i s/callback=partial/partial/g cassandra-driver-2.7.2/cassandra/cluster.py
RUN zip -f cassandra-driver-internal-only-2.7.2.zip cassandra-driver-2.7.2/cassandra/cluster.py

RUN mkdir -p /opt/jolokia/

ADD http://search.maven.org/remotecontent?filepath=org/jolokia/jolokia-jvm/1.3.2/jolokia-jvm-1.3.2-agent.jar /opt/jolokia/jolokia-jvm-agent.jar
RUN chmod 744 /opt/jolokia/jolokia-jvm-agent.jar
RUN echo "f00fbaaf8c136d23f5f5ed9bacbc012a /opt/jolokia/jolokia-jvm-agent.jar" > /tmp/jolokia-jvm-agent.jar.md5
RUN md5sum --check /tmp/jolokia-jvm-agent.jar.md5
RUN rm -f /tmp/jolokia-jvm-agent.jar.md5

ADD cassandra_template.yaml /etc/cassandra/
# Slightly modified in order to run jolokia
ADD cassandra-env.sh /etc/cassandra/

# Override logging: STDOUT only
ADD logback.xml /etc/cassandra/

RUN rm -f /etc/cassandra/cassandra.yaml && chmod 0777 /etc/cassandra

COPY planb-cassandra.sh /usr/local/bin/

CMD planb-cassandra.sh

COPY scm-source.json /
