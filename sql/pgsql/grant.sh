#!/bin/sh
ACCESSTO="
  certificate
  extension
  signing_request
  signature_algorithm
  signature_algorithm_id_seq
"

if [ $# -ne 2 ]; then
  echo "Usage: $(basename $0) <database> <user>"
  exit 1
fi

db=$1
user=$2

for table in ${ACCESSTO}; do
  psql -c "ALTER TABLE ${table} OWNER TO ${user};" ${db}
  psql -c "GRANT ALL PRIVILEGES ON TABLE ${table} TO ${user};" ${db}
done

