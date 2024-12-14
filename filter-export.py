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
    # Type constants
    TYPE_KEY = "type"
    VERSION_TYPE = "version"
    TEAM_TYPE = "team"
    ROLE_TYPE = "role"
    USER_TYPE = "user"
    CHANNEL_TYPE = "channel"
    POST_TYPE = "post"
    DIRECT_CHANNEL_TYPE = "direct_channel"
    DIRECT_POST_TYPE = "direct_post"

    # Common dictionary keys
    TEAM_KEY = "team"
    ROLE_KEY = "role"
    USER_KEY = "user"
    CHANNEL_KEY = "channel"
    POST_KEY = "post"
    DIRECT_CHANNEL_KEY = "direct_channel"
    DIRECT_POST_KEY = "direct_post"
    NAME_KEY = "name"
    USERNAME_KEY = "username"
    MEMBERS_KEY = "members"
    CHANNEL_MEMBERS_KEY = "channel_members"

    def __init__(
        self,
        jsonl_filepath: Path,
        output_filepath: Path,
        team: Optional[List[str]] = None,
        teams: bool = False,
        role: Optional[List[str]] = None,
        roles: bool = False,
        user: Optional[List[str]] = None,
        users: bool = False,
        channel: Optional[List[str]] = None,
        channels: bool = False,
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
        :param user: List of usernames to whitelist.
        :type user: Optional[List[str]]
        :param users: If True, whitelist all user entries.
        :type users: bool
        :param channel: List of channel team:name strings to whitelist.
        :type channel: Optional[List[str]]
        :param channels: If True, whitelist all channel entries.
        :type channels: bool
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
        self.user = user or []
        self.users = users
        self.channel = channel or []
        self.channels = channels
        self.post = post or []
        self.posts = posts
        self.direct_channel = [frozenset(dc.split(':')) for dc in (direct_channel or [])]
        self.direct_channels = direct_channels
        self.direct_post = [frozenset(dp.split(':')) for dp in (direct_post or [])]
        self.direct_posts = direct_posts
        self.debug = debug
        self.version_entry: Optional[Dict[str, Any]] = None
        
        # Setup dispatch dictionary for filter methods
        self._filter_dispatch = {
            self.TEAM_TYPE: self._filter_team,
            self.ROLE_TYPE: self._filter_role,
            self.USER_TYPE: self._filter_user,
            self.CHANNEL_TYPE: self._filter_channel,
            self.POST_TYPE: self._filter_post,
            self.DIRECT_CHANNEL_TYPE: self._filter_direct_channel,
            self.DIRECT_POST_TYPE: self._filter_direct_post,
        }
        
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

    def _process_version_entry(self, entry: Dict[str, Any], outfile) -> None:
        """
        Handle version entry processing and writing.

        :param entry: The version entry to process
        :type entry: Dict[str, Any]
        :param outfile: The output file handle
        """
        self.version_entry = entry
        logging.debug(f"Found version entry: {self.version_entry}")
        outfile.write(json.dumps(self.version_entry) + "\n")

    def _process_line(self, line: str, line_number: int, outfile) -> None:
        """
        Process a single line from the JSONL file.

        :param line: The line to process
        :type line: str
        :param line_number: The current line number
        :type line_number: int
        :param outfile: The output file handle
        """
        try:
            entry = json.loads(line)
            logging.debug(f"Processing line {line_number}: {entry.get('type', 'no type')}")
            
            if entry.get("type") == "version":
                self._process_version_entry(entry, outfile)
            elif self._filter_entry(entry):
                outfile.write(json.dumps(entry) + "\n")
                logging.debug(f"Line {line_number} included in output.")
            else:
                logging.debug(f"Line {line_number} excluded from output.")
        except json.JSONDecodeError as e:
            logging.error(f"JSONDecodeError on line {line_number}: {e}")

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
                    self._process_line(line, line_number, outfile)
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
        entry_type = entry.get(self.TYPE_KEY)
        if not entry_type:
            logging.debug("Entry has no type, excluding.")
            return False

        filter_func = self._filter_dispatch.get(entry_type)
        if filter_func:
            return filter_func(entry)

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
        team_name = entry.get(self.TEAM_KEY, {}).get(self.NAME_KEY)
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
        role_name = entry.get(self.ROLE_KEY, {}).get(self.NAME_KEY)
        if role_name in self.role:
            logging.debug(f"Role '{role_name}' matches filter, including.")
            return True
        logging.debug(f"Role '{role_name}' does not match filter, excluding.")
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
        username = entry.get(self.USER_KEY, {}).get(self.USERNAME_KEY)
        if username in self.user:
            logging.debug(f"User '{username}' matches filter, including.")
            return True
        logging.debug(f"User '{username}' does not match filter, excluding.")
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
        channel_team = entry.get(self.CHANNEL_KEY, {}).get(self.TEAM_KEY)
        channel_name = entry.get(self.CHANNEL_KEY, {}).get(self.NAME_KEY)
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
        post_team = entry.get(self.POST_KEY, {}).get(self.TEAM_KEY)
        post_channel = entry.get(self.POST_KEY, {}).get(self.CHANNEL_KEY)
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
        members = entry.get(self.DIRECT_CHANNEL_KEY, {}).get(self.MEMBERS_KEY)
        if members and isinstance(members, list):
            members_set = frozenset(members)
            if members_set in self.direct_channel:
                logging.debug(
                    f"Direct channel with members '{sorted(members)}' matches filter, including."
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
        channel_members = entry.get(self.DIRECT_POST_KEY, {}).get(self.CHANNEL_MEMBERS_KEY)
        if channel_members and isinstance(channel_members, list):
            members_set = frozenset(channel_members)
            if members_set in self.direct_post:
                logging.debug(
                    f"Direct post with members '{sorted(channel_members)}' matches filter, including."
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


def _setup_argument_parser() -> argparse.ArgumentParser:
    """
    Set up and return the argument parser with all arguments configured.

    :return: Configured argument parser
    :rtype: argparse.ArgumentParser
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
    
    # Team arguments
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
    
    # Role arguments
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
    
    # User arguments
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
    
    # Channel arguments
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
    
    # Post arguments
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
    
    # Direct channel arguments
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
    
    # Direct post arguments
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
    
    return parser

def _validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """
    Validate command line arguments for conflicting options.

    :param args: Parsed command line arguments
    :type args: argparse.Namespace
    :param parser: Argument parser for error reporting
    :type parser: argparse.ArgumentParser
    :raises: argparse.ArgumentError if validation fails
    """
    conflicting_pairs = [
        (args.team, args.teams),
        (args.role, args.roles),
        (args.user, args.users),
        (args.channel, args.channels),
        (args.post, args.posts),
        (args.direct_channel, args.direct_channels),
        (args.direct_post, args.direct_posts),
    ]
    
    if any(pair[0] and pair[1] for pair in conflicting_pairs):
        parser.error(
            "You cannot use both singular and plural versions of the same filter argument."
        )

def _run_filter(args: argparse.Namespace) -> int:
    """
    Create and run the MattermostFilter with the provided arguments.

    :param args: Parsed command line arguments
    :type args: argparse.Namespace
    :return: Exit code (0 for success, 1 for failure)
    :rtype: int
    """
    try:
        filter_obj = MattermostFilter(
            jsonl_filepath=args.jsonl_filepath,
            output_filepath=args.output,
            team=args.team,
            teams=args.teams,
            role=args.role,
            roles=args.roles,
            user=args.user,
            users=args.users,
            channel=args.channel,
            channels=args.channels,
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

def main() -> int:
    """
    Main function to parse command-line arguments and run the Mattermost filter.

    :return: Exit code (0 for success, 1 for failure).
    :rtype: int
    """
    parser = _setup_argument_parser()
    args = parser.parse_args()
    
    try:
        _validate_args(args, parser)
        return _run_filter(args)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return 1


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
