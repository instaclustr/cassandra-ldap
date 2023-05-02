#!/bin/bash

mvn clean install \
  -Dversion.cassandra22=2.2.19 \
  -Dversion.cassandra30=3.0.28 \
  -Dversion.cassandra311=3.11.14 \
  -Dversion.cassandra4=4.0.7 \
  -Dversion.cassandra41=4.1.0
