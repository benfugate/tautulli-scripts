#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Description:  Automatically change episode artwork in Plex to hide spoilers.
# Author:       /u/SwiftPanda16
# Requires:     plexapi, requests
# Tautulli script trigger:
#    * Notify on recently added
#    * Notify on watched (optional - to remove the artwork after being watched)
# Tautulli script conditions:
#    * Condition {1}:
#        [Media Type | is | show or season or episode]
#    * Condition {2} (optional):
#        [ Library Name | is | DVR ]
#        [ Show Namme | is | Game of Thrones ]
# Tautulli script arguments:
#    * Recently Added:
#        To use an image file (can be image in the same directory as this script, or full path to an image):
#            --rating_key {rating_key} --image spoilers.png
#        To blur the episode artwork (optional blur in pixels):
#            --rating_key {rating_key} --blur 25
#        To remove the summary:
#            --rating_key {rating_key} --summary_remove"
#    * Watched (optional):
#        --rating_key {rating_key} --remove
# Note:
#    * "Use local assets" must be enabled for the library in Plex (Manage Library > Edit > Advanced > Use local assets).

import argparse
import os
import requests
import shutil
import re
from plexapi.server import PlexServer

PLEX_URL = ''
PLEX_TOKEN = ''

# Environmental Variables
PLEX_URL = os.getenv('PLEX_URL', PLEX_URL)
PLEX_TOKEN = os.getenv('PLEX_TOKEN', PLEX_TOKEN)


def modify_episode_artwork(plex, rating_key, image=None, blur=None, summary_remove=False, remove=False):
    item = plex.fetchItem(rating_key)

    if item.type == 'show':
        episodes = item.episodes()
    elif item.type == 'season':
        episodes = item.episodes()
    elif item.type == 'episode':
        episodes = [item]
    else:
        print('Only media type show, season, or episode is supported: '
              '{item.title} ({item.ratingKey}) is media type {item.type}.'.format(item=item))
        return

    for episode in episodes:
        changes = False
        for part in episode.iterParts():
            episode_filepath = part.file
            episode_folder = os.path.dirname(episode_filepath)
            episode_filename = os.path.splitext(os.path.basename(episode_filepath))[0]

            if remove:
                # Find image files with the same name as the episode
                for filename in os.listdir(episode_folder):
                    if filename.startswith(episode_filename) and filename.endswith(('.jpg', '.png')):
                        # Delete the episode artwork image file
                        os.remove(os.path.join(episode_folder, filename))

                # Unlock the summary so it will get updated on refresh
                episode.edit(**{'summary.locked': 0})
                episode.refresh()
                continue

            if image:
                # File path to episode artwork using the same episode file name
                episode_artwork = os.path.splitext(episode_filepath)[0] + os.path.splitext(image)[1]
                episode_number = re.search(".*(S\d+E\d+).*", episode_artwork).group(1)

                # Check if existing image of a lower episode quality is present... if it is, just change that image name.
                if not os.path.islink(episode_artwork):
                    files = [filename for filename in os.listdir(episode_folder)]
                    for file in files:
                        if re.search(f".*({episode_number}).*\.jpg|png", file):
                            print(f"REMOVING... {file}")
                            os.remove(os.path.join(episode_folder, file))
                            break

                    # Copy the image to the episode artwork
                    print(f"CREATING SYMLINK... {episode_artwork}")
                    os.symlink("/media/posters/" + image, episode_artwork)
                    changes = True

            elif blur:
                # File path to episode artwork using the same episode file name
                episode_artwork = os.path.splitext(episode_filepath)[0] + '.png'
                # Get the blurred artwork
                image_url = plex.transcodeImage(
                    episode.thumbUrl,
                    height=270,
                    width=480,
                    blur=blur,
                    imageFormat='png'
                )
                r = requests.get(image_url, stream=True)
                if r.status_code == 200:
                    r.raw.decode_content = True
                    # Copy the image to the episode artwork
                    with open(episode_artwork, 'wb') as f:
                        shutil.copyfileobj(r.raw, f)
                changes = True

            if summary_remove:
                # Use a zero-width space (\u200b) for blank lines
                episode.edit(**{
                    'summary.value': '',
                    'summary.locked': 1
                })

        # Refresh metadata for the episode
        if changes:
            episode.refresh()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--rating_key', required=True, type=int)
    parser.add_argument('--image')
    parser.add_argument('--blur', type=int, default=25)
    parser.add_argument('--summary_remove', action='store_true')
    parser.add_argument('--remove', action='store_true')
    opts = parser.parse_args()

    plex = PlexServer(PLEX_URL, PLEX_TOKEN)
    modify_episode_artwork(plex, **vars(opts))
