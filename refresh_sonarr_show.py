import argparse
from pyarr import SonarrAPI

parser = argparse.ArgumentParser()
parser.add_argument('SonarrHostUrl')
parser.add_argument('SonarrApiKey')
parser.add_argument('--show-name')
args = parser.parse_args()

sonarr = SonarrAPI(args.SonarrHostUrl, args.SonarrApiKey)

# This show name is super inconsistent and I'm over it
if args.show_name == "Big Brother":
    args.show_name = "Big Brother (US)"

show = 0
request = sonarr.get_series()
for series in request:
    if args.show_name == series["title"]:
        show = series["id"]
        break

if not show:
    print(f"Show not found... {args.show_name}")
    exit(2)

request = {"seriesId": show}
sonarr.post_command("RescanSeries", **request)
