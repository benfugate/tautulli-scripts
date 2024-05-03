#!/bin/bash
curl --silent --output /dev/null helios.fugate.net:8989/api/command?apikey=$1 -d '{"name": "RescanSeries", "seriesId": "35" }'
exit 0
