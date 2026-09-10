#!/usr/bin/env bash
# probe_server.sh - proba "live" a serviciului protejat h1:8080.
# Ruleaza pe o gazda-client (h2). La fiecare secunda incearca o conexiune TCP
# si scrie OK daca reuseste sau FAIL daca expira (serviciul e indisponibil).
#
# Apel din CLI-ul Mininet:   mininet> h2 bash demo/probe_server.sh
DST=10.0.0.1
PORT=8080
N=${1:-40}          # numar de incercari (implicit 40, o secunda fiecare)
for i in $(seq 1 "$N"); do
  if timeout 1 bash -c ">/dev/tcp/${DST}/${PORT}" 2>/dev/null; then
    echo "$(date +%T)  try $i  ->  OK   (connected)"
  else
    echo "$(date +%T)  try $i  ->  FAIL (no access)"
  fi
  sleep 1
done