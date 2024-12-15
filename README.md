# Mattermost Export Filter

A Python tool for filtering Mattermost server export data.

This tool allows you to selectively extract specific types of data from a Mattermost export file, creating a new filtered export that can be imported into another Mattermost server.

## Features

- Filter Mattermost export data by:
  - Teams
  - Roles
  - Users
  - Channels
  - Posts
  - Direct channels
  - Direct messages
- Preserves all attachments for included posts
- Maintains export format compatibility
- Detailed logging and statistics
- Flexible command-line interface

## Prerequisites

- Python 3.9 or higher
- A directory containing the unzipped [Mattermost server export](https://docs.mattermost.com/manage/mmctl-command-line-tool.html#mmctl-export), which contains:
  - `import.jsonl` file
  - `data/` directory with attachments

## Installation

Clone this repository:

```bash
git clone <repository-url>
cd <repository-name>
```

No additional dependencies are required beyond Python's standard library.

## Usage

Basic usage:

```bash
./filter-export.py <input-dir> --output <output-dir> [filter options]
```

### Filter Options

You can combine multiple filter options. Each filter type has two forms:
- Specific filtering with `--option <value>` (can be used multiple times)
- Include all with `--options` (plural form)

#### Team Filtering

- `--team <team-name>` - Include specific team(s)
- `--teams` - Include all teams

#### Role Filtering

- `--role <role-name>` - Include specific role(s)
- `--roles` - Include all roles

#### User Filtering

- `--user <username>` - Include specific user(s)
- `--users` - Include all users

#### Channel Filtering

- `--channel <team:channel>` - Include specific channel(s)
- `--channels` - Include all channels

#### Post Filtering

- `--post <team:channel>` - Include posts from specific channel(s)
- `--posts` - Include all posts

#### Direct Channel Filtering

- `--direct-channel <user1:user2>` - Include specific direct channel(s)
- `--direct-channels` - Include all direct channels

#### Direct Post Filtering

- `--direct-post <user1:user2>` - Include direct posts between specific users
- `--direct-posts` - Include all direct posts

### Additional Options

- `--include-system-messages` - Include system-generated messages
- `--debug` - Enable debug logging
- `--output <dir>` - Specify output directory (default: "output")

### Examples

Include all posts from a specific channel:

```bash
./filter-export.py mattermost-export --post "engineering:general"
```

Export all data for specific users:

```bash
./filter-export.py mattermost-export --user john.doe --user jane.smith
```

Export a single team, no data:

```bash
./filter-export.py mattermost-export --team engineering
```

## Output

The tool creates a new Mattermost-compatible export containing:
- Filtered `import.jsonl` file
- `data/` directory with relevant attachments

These can be compressed into a zip file, then [uploaded/imported](https://docs.mattermost.com/manage/mmctl-command-line-tool.html#mmctl-import) to a Mattermost server.

## Notes

- The version entry from the original export is always included
- System messages are excluded by default unless `--include-system-messages` is used
- Attachments from included posts are automatically copied to the output
- The tool maintains referential integrity for included entries

## Error Handling

- Invalid input directory structure will raise appropriate errors
- Missing attachments are logged but won't stop processing
- Conflicting filter options (e.g., --user and --users) will raise an error
