#!/bin/bash

mvn clean install \
  -Dversion.cassandra22=2.2.19 \
  -Dversion.cassandra30=3.0.31 \
  -Dversion.cassandra311=3.11.18 \
  -Dversion.cassandra4=4.0.16 \
  -Dversion.cassandra41=4.1.0
