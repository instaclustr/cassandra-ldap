#!/bin/bash

mvn clean install \
  -Dversion.cassandra22=2.2.19 \
  -Dversion.cassandra30=3.0.23 \
  -Dversion.cassandra311=3.11.10 \
  -Dversion.cassandra4=4.0-rc2