FROM registry.opensource.zalan.do/stups/openjdk:8u66-b17-1-10

MAINTAINER Zalando SE

# Storage Port, JMX, Jolokia Agent, Thrift, CQL Native, OpsCenter Agent
# Left out: SSL
EXPOSE 7001 9042

ENV CASSIE_VERSION=2.1.13

ENV DEBIAN_FRONTEND=noninteractive
RUN echo "deb http://debian.datastax.com/community stable main" | tee -a /etc/apt/sources.list.d/datastax.community.list
RUN curl -sL https://debian.datastax.com/debian/repo_key | apt-key add -
RUN apt-get -y update && apt-get -y -o Dpkg::Options::='--force-confold' --fix-missing dist-upgrade
RUN apt-get -y install cassandra=$CASSIE_VERSION cassandra-tools=$CASSIE_VERSION sysstat && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN mkdir -p /opt/jolokia/

ADD http://search.maven.org/remotecontent?filepath=org/jolokia/jolokia-jvm/1.3.2/jolokia-jvm-1.3.2-agent.jar /opt/jolokia/jolokia-jvm-agent.jar
RUN chmod 744 /opt/jolokia/jolokia-jvm-agent.jar
RUN echo "f00fbaaf8c136d23f5f5ed9bacbc012a /opt/jolokia/jolokia-jvm-agent.jar" > /tmp/jolokia-jvm-agent.jar.md5
RUN md5sum --check /tmp/jolokia-jvm-agent.jar.md5
RUN rm -f /tmp/jolokia-jvm-agent.jar.md5

RUN chmod -R 777 /var/lib/cassandra
RUN chmod -R 777 /var/log/cassandra

ADD cassandra_template.yaml /etc/cassandra/
# Slightly modified in order to run jolokia
ADD cassandra-env.sh /etc/cassandra/

RUN rm -f /etc/cassandra/cassandra.yaml && chmod 0777 /etc/cassandra

COPY planb-cassandra.sh /usr/local/bin/

CMD planb-cassandra.sh

COPY scm-source.json /
