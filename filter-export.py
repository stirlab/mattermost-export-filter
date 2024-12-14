#!/usr/bin/env python3

"""
This script reads a Mattermost JSONL export file, filters entries based on
command-line arguments, and produces a new JSONL file containing only the
selected entries. It supports filtering by:
 - team
 - role
 - user
 - channel
 - post
 - direct channel
 - direct post.
It always includes the version entry in the output file.
"""

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional


class MattermostFilter:
    """
    Encapsulates the core functionality of the Mattermost JSONL filter script.
    """

    def __init__(
        self,
        jsonl_filepath: Path,
        output_filepath: Path,
        team: Optional[List[str]] = None,
        teams: bool = False,
        role: Optional[List[str]] = None,
        roles: bool = False,
        channel: Optional[List[str]] = None,
        channels: bool = False,
        user: Optional[List[str]] = None,
        users: bool = False,
        post: Optional[List[str]] = None,
        posts: bool = False,
        direct_channel: Optional[List[str]] = None,
        direct_channels: bool = False,
        direct_post: Optional[List[str]] = None,
        direct_posts: bool = False,
        debug: bool = False,
    ) -> None:
        """
        Initializes the MattermostFilter with file paths and filter criteria.

        :param jsonl_filepath: Path to the input JSONL file.
        :type jsonl_filepath: Path
        :param output_filepath: Path to the output JSONL file.
        :type output_filepath: Path
        :param team: List of team names to whitelist.
        :type team: Optional[List[str]]
        :param teams: If True, whitelist all team entries.
        :type teams: bool
        :param role: List of role names to whitelist.
        :type role: Optional[List[str]]
        :param roles: If True, whitelist all role entries.
        :type roles: bool
        :param channel: List of channel team:name strings to whitelist.
        :type channel: Optional[List[str]]
        :param channels: If True, whitelist all channel entries.
        :type channels: bool
        :param user: List of usernames to whitelist.
        :type user: Optional[List[str]]
        :param users: If True, whitelist all user entries.
        :type users: bool
        :param post: List of post team:channel strings to whitelist.
        :type post: Optional[List[str]]
        :param posts: If True, whitelist all post entries.
        :type posts: bool
        :param direct_channel: List of direct channel member lists to whitelist.
        :type direct_channel: Optional[List[str]]
        :param direct_channels: If True, whitelist all direct channel entries.
        :type direct_channels: bool
        :param direct_post: List of direct post member lists to whitelist.
        :type direct_post: Optional[List[str]]
        :param direct_posts: If True, whitelist all direct post entries.
        :type direct_posts: bool
        :param debug: Enable debug logging.
        :type debug: bool
        """
        self.jsonl_filepath = jsonl_filepath
        self.output_filepath = output_filepath
        self.team = team or []
        self.teams = teams
        self.role = role or []
        self.roles = roles
        self.channel = channel or []
        self.channels = channels
        self.user = user or []
        self.users = users
        self.post = post or []
        self.posts = posts
        self.direct_channel = direct_channel or []
        self.direct_channels = direct_channels
        self.direct_post = direct_post or []
        self.direct_posts = direct_posts
        self.debug = debug
        self.version_entry: Optional[Dict[str, Any]] = None
        self._setup_logging()

    def _setup_logging(self) -> None:
        """
        Sets up the logging configuration.
        """
        log_level = logging.DEBUG if self.debug else logging.INFO
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        logging.debug("Logging setup complete.")

    def _read_and_filter_jsonl(self) -> None:
        """
        Reads the input JSONL file line by line, filters each entry, and
        appends the filtered entries to the output JSONL file.
        """
        logging.debug(f"Reading input file: {self.jsonl_filepath}")
        try:
            with open(self.jsonl_filepath, "r", encoding="utf-8") as infile, open(
                self.output_filepath, "w", encoding="utf-8"
            ) as outfile:
                for line_number, line in enumerate(infile, start=1):
                    try:
                        entry = json.loads(line)
                        logging.debug(
                            f"Processing line {line_number}: {entry.get('type', 'no type')}"
                        )
                        if entry.get("type") == "version":
                            self.version_entry = entry
                            logging.debug(f"Found version entry: {self.version_entry}")
                            outfile.write(json.dumps(self.version_entry) + "\n")
                        elif self._filter_entry(entry):
                            outfile.write(json.dumps(entry) + "\n")
                            logging.debug(f"Line {line_number} included in output.")
                        else:
                            logging.debug(f"Line {line_number} excluded from output.")
                    except json.JSONDecodeError as e:
                        logging.error(f"JSONDecodeError on line {line_number}: {e}")
                        continue
        except FileNotFoundError:
            logging.error(f"Input file not found: {self.jsonl_filepath}")
            exit(1)
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            exit(1)
        logging.debug("Finished reading and filtering JSONL file.")

    def _filter_entry(self, entry: Dict[str, Any]) -> bool:
        """
        Filters a single JSONL entry based on the provided criteria.

        :param entry: The JSONL entry to filter.
        :type entry: Dict[str, Any]
        :return: True if the entry should be included, False otherwise.
        :rtype: bool
        """
        entry_type = entry.get("type")
        if not entry_type:
            logging.debug("Entry has no type, excluding.")
            return False

        if entry_type == "team":
            return self._filter_team(entry)
        if entry_type == "role":
            return self._filter_role(entry)
        if entry_type == "channel":
            return self._filter_channel(entry)
        if entry_type == "user":
            return self._filter_user(entry)
        if entry_type == "post":
            return self._filter_post(entry)
        if entry_type == "direct_channel":
            return self._filter_direct_channel(entry)
        if entry_type == "direct_post":
            return self._filter_direct_post(entry)
        logging.debug(f"Entry type '{entry_type}' not handled, excluding.")
        return False

    def _filter_team(self, entry: Dict[str, Any]) -> bool:
        """
        Filters a team entry based on the provided team names or the teams flag.

        :param entry: The team entry to filter.
        :type entry: Dict[str, Any]
        :return: True if the entry should be included, False otherwise.
        :rtype: bool
        """
        if self.teams:
            logging.debug("Teams flag is set, including all team entries.")
            return True
        if not self.team:
            logging.debug("No team filter specified, excluding team entry.")
            return False
        team_name = entry.get("team", {}).get("name")
        if team_name in self.team:
            logging.debug(f"Team '{team_name}' matches filter, including.")
            return True
        logging.debug(f"Team '{team_name}' does not match filter, excluding.")
        return False

    def _filter_role(self, entry: Dict[str, Any]) -> bool:
        """
        Filters a role entry based on the provided role names or the roles flag.

        :param entry: The role entry to filter.
        :type entry: Dict[str, Any]
        :return: True if the entry should be included, False otherwise.
        :rtype: bool
        """
        if self.roles:
            logging.debug("Roles flag is set, including all role entries.")
            return True
        if not self.role:
            logging.debug("No role filter specified, excluding role entry.")
            return False
        role_name = entry.get("role", {}).get("name")
        if role_name in self.role:
            logging.debug(f"Role '{role_name}' matches filter, including.")
            return True
        logging.debug(f"Role '{role_name}' does not match filter, excluding.")
        return False

    def _filter_channel(self, entry: Dict[str, Any]) -> bool:
        """
        Filters a channel entry based on the provided team:name strings or the channels flag.

        :param entry: The channel entry to filter.
        :type entry: Dict[str, Any]
        :return: True if the entry should be included, False otherwise.
        :rtype: bool
        """
        if self.channels:
            logging.debug("Channels flag is set, including all channel entries.")
            return True
        if not self.channel:
            logging.debug("No channel filter specified, excluding channel entry.")
            return False
        channel_team = entry.get("channel", {}).get("team")
        channel_name = entry.get("channel", {}).get("name")
        if channel_team and channel_name:
            channel_team_name = f"{channel_team}:{channel_name}"
            if channel_team_name in self.channel:
                logging.debug(
                    f"Channel '{channel_team_name}' matches filter, including."
                )
                return True
        logging.debug(
            f"Channel '{channel_team}:{channel_name}' does not match filter, excluding."
        )
        return False

    def _filter_user(self, entry: Dict[str, Any]) -> bool:
        """
        Filters a user entry based on the provided usernames or the users flag.

        :param entry: The user entry to filter.
        :type entry: Dict[str, Any]
        :return: True if the entry should be included, False otherwise.
        :rtype: bool
        """
        if self.users:
            logging.debug("Users flag is set, including all user entries.")
            return True
        if not self.user:
            logging.debug("No user filter specified, excluding user entry.")
            return False
        username = entry.get("user", {}).get("username")
        if username in self.user:
            logging.debug(f"User '{username}' matches filter, including.")
            return True
        logging.debug(f"User '{username}' does not match filter, excluding.")
        return False

    def _filter_post(self, entry: Dict[str, Any]) -> bool:
        """
        Filters a post entry based on the provided team:channel strings or the posts flag.

        :param entry: The post entry to filter.
        :type entry: Dict[str, Any]
        :return: True if the entry should be included, False otherwise.
        :rtype: bool
        """
        if self.posts:
            logging.debug("Posts flag is set, including all post entries.")
            return True
        if not self.post:
            logging.debug("No post filter specified, excluding post entry.")
            return False
        post_team = entry.get("post", {}).get("team")
        post_channel = entry.get("post", {}).get("channel")
        if post_team and post_channel:
            post_team_channel = f"{post_team}:{post_channel}"
            if post_team_channel in self.post:
                logging.debug(f"Post '{post_team_channel}' matches filter, including.")
                return True
        logging.debug(
            f"Post '{post_team}:{post_channel}' does not match filter, excluding."
        )
        return False

    def _filter_direct_channel(self, entry: Dict[str, Any]) -> bool:
        """
        Filters a direct channel entry based on the provided member lists or the direct_channels flag.

        :param entry: The direct channel entry to filter.
        :type entry: Dict[str, Any]
        :return: True if the entry should be included, False otherwise.
        :rtype: bool
        """
        if self.direct_channels:
            logging.debug(
                "Direct channels flag is set, including all direct channel entries."
            )
            return True
        if not self.direct_channel:
            logging.debug(
                "No direct channel filter specified, excluding direct channel entry."
            )
            return False
        members = entry.get("direct_channel", {}).get("members")
        if members and isinstance(members, list):
            members_str = ":".join(sorted(members))
            if members_str in self.direct_channel:
                logging.debug(
                    f"Direct channel with members '{members_str}' matches filter, including."
                )
                return True
        logging.debug(
            f"Direct channel with members '{members}' does not match filter, excluding."
        )
        return False

    def _filter_direct_post(self, entry: Dict[str, Any]) -> bool:
        """
        Filters a direct post entry based on the provided member lists or the direct_posts flag.

        :param entry: The direct post entry to filter.
        :type entry: Dict[str, Any]
        :return: True if the entry should be included, False otherwise.
        :rtype: bool
        """
        if self.direct_posts:
            logging.debug(
                "Direct posts flag is set, including all direct post entries."
            )
            return True
        if not self.direct_post:
            logging.debug(
                "No direct post filter specified, excluding direct post entry."
            )
            return False
        channel_members = entry.get("direct_post", {}).get("channel_members")
        if channel_members and isinstance(channel_members, list):
            members_str = ":".join(sorted(channel_members))
            if members_str in self.direct_post:
                logging.debug(
                    f"Direct post with members '{members_str}' matches filter, including."
                )
                return True
        logging.debug(
            f"Direct post with members '{channel_members}' does not match filter, excluding."
        )
        return False

    def run(self) -> None:
        """
        Runs the Mattermost JSONL filtering process.
        """
        logging.debug("Starting Mattermost JSONL filtering process.")
        self._read_and_filter_jsonl()
        logging.debug("Mattermost JSONL filtering process completed.")


def main() -> int:
    """
    Main function to parse command-line arguments and run the Mattermost filter.

    :return: Exit code (0 for success, 1 for failure).
    :rtype: int
    """
    parser = argparse.ArgumentParser(
        description="Filters a Mattermost JSONL export file based on specified criteria."
    )
    parser.add_argument(
        "jsonl_filepath", type=Path, help="Path to the input JSONL file."
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Path to the output JSONL file.",
        default=Path("filtered_output.jsonl"),
    )
    parser.add_argument(
        "--team",
        type=str,
        action="append",
        help="Whitelist team entries with a matching name. Can be specified multiple times.",
    )
    parser.add_argument(
        "--teams",
        action="store_true",
        help="Whitelist all team entries.",
    )
    parser.add_argument(
        "--role",
        type=str,
        action="append",
        help="Whitelist role entries with a matching name. Can be specified multiple times.",
    )
    parser.add_argument(
        "--roles",
        action="store_true",
        help="Whitelist all role entries.",
    )
    parser.add_argument(
        "--channel",
        type=str,
        action="append",
        help="Whitelist channel entries with a matching team:name. Can be specified multiple times.",
    )
    parser.add_argument(
        "--channels",
        action="store_true",
        help="Whitelist all channel entries.",
    )
    parser.add_argument(
        "--user",
        type=str,
        action="append",
        help="Whitelist user entries with a matching username. Can be specified multiple times.",
    )
    parser.add_argument(
        "--users",
        action="store_true",
        help="Whitelist all user entries.",
    )
    parser.add_argument(
        "--post",
        type=str,
        action="append",
        help="Whitelist post entries with a matching team:channel. Can be specified multiple times.",
    )
    parser.add_argument(
        "--posts",
        action="store_true",
        help="Whitelist all post entries.",
    )
    parser.add_argument(
        "--direct-channel",
        type=str,
        action="append",
        help="Whitelist direct channel entries with matching members. Can be specified multiple times.",
    )
    parser.add_argument(
        "--direct-channels",
        action="store_true",
        help="Whitelist all direct channel entries.",
    )
    parser.add_argument(
        "--direct-post",
        type=str,
        action="append",
        help="Whitelist direct post entries with matching members. Can be specified multiple times.",
    )
    parser.add_argument(
        "--direct-posts",
        action="store_true",
        help="Whitelist all direct post entries.",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")

    args = parser.parse_args()

    if (
        (args.team and args.teams)
        or (args.role and args.roles)
        or (args.channel and args.channels)
        or (args.user and args.users)
        or (args.post and args.posts)
        or (args.direct_channel and args.direct_channels)
        or (args.direct_post and args.direct_posts)
    ):
        parser.error(
            "You cannot use both singular and plural versions of the same filter argument."
        )
        return 1

    try:
        filter_obj = MattermostFilter(
            jsonl_filepath=args.jsonl_filepath,
            output_filepath=args.output,
            team=args.team,
            teams=args.teams,
            role=args.role,
            roles=args.roles,
            channel=args.channel,
            channels=args.channels,
            user=args.user,
            users=args.users,
            post=args.post,
            posts=args.posts,
            direct_channel=args.direct_channel,
            direct_channels=args.direct_channels,
            direct_post=args.direct_post,
            direct_posts=args.direct_posts,
            debug=args.debug,
        )
        filter_obj.run()
        logging.info(f"Filtered output written to: {args.output}")
        return 0
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return 1


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
