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
    # File and directory constants
    IMPORT_JSONL = "import.jsonl"
    DATA_DIR = "data"

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

    # Statistics constants
    STATS_ATTACHMENTS = "attachments"

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
        input_dir: Path,
        output_dir: Path,
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
        include_system_messages: bool = False,
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
        :param include_system_messages: If True, include system messages.
        :type include_system_messages: bool
        :param debug: Enable debug logging.
        :type debug: bool
        """
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.input_jsonl = input_dir / self.IMPORT_JSONL
        self.input_data_dir = input_dir / self.DATA_DIR
        self.output_jsonl = output_dir / self.IMPORT_JSONL
        self.output_data_dir = output_dir / self.DATA_DIR
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
        self.include_system_messages = include_system_messages
        self.version_entry: Optional[Dict[str, Any]] = None

        # Initialize statistics
        self.stats = {
            self.TEAM_TYPE: 0,
            self.ROLE_TYPE: 0,
            self.USER_TYPE: 0,
            self.CHANNEL_TYPE: 0,
            self.POST_TYPE: 0,
            self.DIRECT_CHANNEL_TYPE: 0,
            self.DIRECT_POST_TYPE: 0,
            self.STATS_ATTACHMENTS: 0,
        }

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
                entry_type = entry.get(self.TYPE_KEY)
                if entry_type in self.stats:
                    self.stats[entry_type] += 1
                self._process_attachments(entry)
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
        logging.debug(f"Reading input file: {self.input_jsonl}")
        try:
            with open(self.input_jsonl, "r", encoding="utf-8") as infile, open(
                self.output_jsonl, "w", encoding="utf-8"
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

    def _is_system_message(self, entry: Dict[str, Any]) -> bool:
        """
        Check if the entry is a system message.

        :param entry: The entry to check
        :type entry: Dict[str, Any]
        :return: True if the entry is a system message, False otherwise
        :rtype: bool
        """
        entry_type = entry.get(self.TYPE_KEY)
        if entry_type == self.POST_TYPE:
            return bool(entry.get(self.POST_KEY, {}).get("type"))
        elif entry_type == self.DIRECT_POST_TYPE:
            return bool(entry.get(self.DIRECT_POST_KEY, {}).get("type"))
        return False

    def _filter_post(self, entry: Dict[str, Any]) -> bool:
        """
        Filters a post entry based on the provided team:channel strings or the posts flag.

        :param entry: The post entry to filter.
        :type entry: Dict[str, Any]
        :return: True if the entry should be included, False otherwise.
        :rtype: bool
        """
        if not self.include_system_messages and self._is_system_message(entry):
            logging.debug("Excluding system message post")
            return False
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
        if not self.include_system_messages and self._is_system_message(entry):
            logging.debug("Excluding system message direct post")
            return False
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

    def _setup_directories(self) -> None:
        """
        Create output directory structure and validate input directories.
        """
        logging.debug(f"Validating input directory structure: {self.input_dir}")
        if not self.input_dir.is_dir():
            raise FileNotFoundError(f"Input directory does not exist: {self.input_dir}")
        if not self.input_jsonl.is_file():
            raise FileNotFoundError(f"Input JSONL file not found: {self.input_jsonl}")
        if not self.input_data_dir.is_dir():
            raise FileNotFoundError(f"Input data directory not found: {self.input_data_dir}")

        logging.debug(f"Creating output directory structure: {self.output_dir}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.output_data_dir.mkdir(parents=True, exist_ok=True)

    def _copy_attachment(self, rel_path: str) -> None:
        """
        Copy a single attachment file, creating directories as needed.

        :param rel_path: Relative path of the attachment within data directory
        :type rel_path: str
        """
        src_path = self.input_data_dir / rel_path
        dst_path = self.output_data_dir / rel_path
        dst_dir = dst_path.parent

        logging.debug(f"Copying attachment: {rel_path}")
        logging.debug(f"Source path: {src_path}")
        logging.debug(f"Destination path: {dst_path}")

        try:
            if not src_path.is_file():
                logging.error(f"Source attachment file not found: {src_path}")
                return

            dst_dir.mkdir(parents=True, exist_ok=True)

            import shutil
            shutil.copy2(src_path, dst_path)
            self.stats[self.STATS_ATTACHMENTS] += 1
            logging.debug(f"Successfully copied attachment to: {dst_path}")

        except PermissionError as e:
            logging.error(f"Permission error copying attachment {rel_path}: {e}")
        except OSError as e:
            logging.error(f"OS error copying attachment {rel_path}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error copying attachment {rel_path}: {e}")

    def _process_attachments(self, entry: Dict[str, Any]) -> None:
        """
        Extract and copy attachments from post/direct_post entries.

        :param entry: The entry to process for attachments
        :type entry: Dict[str, Any]
        """
        entry_type = entry.get(self.TYPE_KEY)
        if entry_type not in (self.POST_TYPE, self.DIRECT_POST_TYPE):
            return

        content = entry.get(self.POST_KEY if entry_type == self.POST_TYPE else self.DIRECT_POST_KEY, {})
        attachments = content.get("attachments", [])

        if attachments:
            logging.debug(f"Processing {len(attachments)} attachments for {entry_type}")
            for attachment in attachments:
                if "path" in attachment:
                    self._copy_attachment(attachment["path"])

    def _print_statistics(self) -> None:
        """
        Print statistics about the filtering operation.
        """
        logging.info("Filtering Statistics:")
        logging.info("--------------------")
        logging.info(f"Team entries:          {self.stats[self.TEAM_TYPE]}")
        logging.info(f"Role entries:          {self.stats[self.ROLE_TYPE]}")
        logging.info(f"User entries:          {self.stats[self.USER_TYPE]}")
        logging.info(f"Channel entries:       {self.stats[self.CHANNEL_TYPE]}")
        logging.info(f"Post entries:          {self.stats[self.POST_TYPE]}")
        logging.info(f"Direct channel entries: {self.stats[self.DIRECT_CHANNEL_TYPE]}")
        logging.info(f"Direct post entries:   {self.stats[self.DIRECT_POST_TYPE]}")
        logging.info("--------------------")
        logging.info(f"Total attachments:     {self.stats[self.STATS_ATTACHMENTS]}")

    def run(self) -> None:
        """
        Runs the Mattermost JSONL filtering process.
        """
        logging.debug("Starting Mattermost JSONL filtering process.")
        self._setup_directories()
        self._read_and_filter_jsonl()
        self._print_statistics()
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
        "input_dir", type=Path, help="Path to input directory containing data/ and import.jsonl"
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Path to output directory (will contain data/ and import.jsonl)",
        default=Path("output"),
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

    parser.add_argument(
        "--include-system-messages",
        action="store_true",
        help="Include system messages in post and direct post entries.",
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
            input_dir=args.input_dir,
            output_dir=args.output,
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
            include_system_messages=args.include_system_messages,
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
