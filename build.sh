#!/bin/bash

mvn clean install \
  -Dversion.cassandra22=2.2.19 \
  -Dversion.cassandra30=3.0.25 \
  -Dversion.cassandra311=3.11.11 \
  -Dversion.cassandra4=4.0.0
