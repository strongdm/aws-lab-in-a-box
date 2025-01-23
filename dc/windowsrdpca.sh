#!/bin/bash
echo "{\"certificate\": $(sdm admin rdp view-ca | jq -Rsa) }"
