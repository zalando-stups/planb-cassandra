FROM registry.opensource.zalan.do/stups/openjdk:latest

MAINTAINER Zalando SE

# SSL Storage Port, JMX, Jolokia Agent, CQL Native
EXPOSE 7001 7199 8778 9042

ENV CASSIE_VERSION=3.0.15
ENV DEBIAN_FRONTEND=noninteractive

RUN echo "deb http://www.apache.org/dist/cassandra/debian 30x main" | tee -a /etc/apt/sources.list.d/apache.cassandra.list
RUN curl https://www.apache.org/dist/cassandra/KEYS | apt-key add -

RUN apt-get -y update && apt-get -y -o Dpkg::Options::='--force-confold' --fix-missing dist-upgrade
RUN apt-get -y install vim less sysstat \
    cassandra=$CASSIE_VERSION \
    cassandra-tools=$CASSIE_VERSION && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN mkdir -p /opt/jolokia/

ADD http://search.maven.org/remotecontent?filepath=org/jolokia/jolokia-jvm/1.3.2/jolokia-jvm-1.3.2-agent.jar /opt/jolokia/jolokia-jvm-agent.jar
RUN chmod 744 /opt/jolokia/jolokia-jvm-agent.jar
RUN echo "f00fbaaf8c136d23f5f5ed9bacbc012a /opt/jolokia/jolokia-jvm-agent.jar" > /tmp/jolokia-jvm-agent.jar.md5
RUN md5sum --check /tmp/jolokia-jvm-agent.jar.md5
RUN rm -f /tmp/jolokia-jvm-agent.jar.md5

COPY cassandra_template.yaml /etc/cassandra/
COPY cassandra_original.yaml /etc/cassandra/
COPY cassandra-env.sh /etc/cassandra/
COPY cassandra-env.sh-original /etc/cassandra/
COPY jvm.options /etc/cassandra/

# Override logging: STDOUT only
COPY logback.xml /etc/cassandra/

RUN rm -f /etc/cassandra/cassandra.yaml \
          /etc/cassandra/cassandra-rackdc.properties && \
    chmod 0777 /etc/cassandra

COPY planb-cassandra.sh /usr/local/bin/

ENV HOME=/var/lib/cassandra
WORKDIR $HOME
RUN echo 'JVM_OPTS="$JVM_OPTS -Duser.home=$HOME"' >>/usr/share/cassandra/cassandra.in.sh

CMD planb-cassandra.sh

COPY scm-source.json /
