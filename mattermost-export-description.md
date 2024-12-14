# Mattermost server data export context

The Mattermost server has as `export` function which can export all data from a Mattermost installation, suitable for import into another Mattermost server.

This export consists of:

* **import.jsonl:** A JSONL file, with one importable entity per line.
* **data:** A directory of data files from the export. The JSONL has mappings to the individual files in this directory.

## Understanding the JSONL Structure

The data is in JSONL format, meaning each line is a valid JSON object. This is great for processing large datasets line by line. Each object has a `"type"` field that indicates what kind of data it represents. Here's a summary of the types, along with brief descriptions of the objects included in each type:

 * **`version`**: Contains metadata about the Mattermost server and the export process.
   * `version`: The export format version.
   * `info`:
     * `generator`: The tool that generated the export.
     * `version`: The Mattermost server version.
     * `created`: The timestamp of the export.
 * **`role`**: Defines a user role and its associated permissions.
   * `role`:
     * `name`: The unique name of the role (e.g., `system_admin`, `team_user`).
     * `display_name`: A human-readable name for the role.
     * `description`: A description of the role.
     * `permissions`: An array of permission strings granted to the role.
     * `scheme_managed`: A boolean indicating if the role is managed by a scheme.
 * **`user`**: Represents a user in the system.
   * `user`:
     * `username`: The unique username of the user.
     * `email`: The user's email address.
     * `auth_service`: The authentication service used by the user (null if local).
     * `nickname`: The user's nickname.
     * `first_name`: The user's first name.
     * `last_name`: The user's last name.
     * `position`: The user's position.
     * `roles`: A space-separated string of user roles.
     * `locale`: The user's locale.
     * `delete_at`: A timestamp indicating when the user was deleted (0 if not deleted).
     * `teams`: An array of teams the user belongs to, with roles and channel information.
     * `notify_props`: Notification preferences for the user.
     * `custom_status`: Optional custom status information.
 * **`team`**: Represents a Mattermost team.
   * `team`:
     * `name`: The unique name of the team.
     * `display_name`: A human-readable name for the team.
     * `type`: The type of team (e.g., "O" for open, "P" for private).
     * `description`: A description of the team.
     * `allow_open_invite`: A boolean indicating if open invites are allowed.
 * **`channel`**: Represents a channel within a team.
   * `channel`:
     * `team`: The name of the team the channel belongs to.
     * `name`: The unique name of the channel.
     * `display_name`: A human-readable name for the channel.
     * `type`: The type of channel (e.g., "O" for open, "P" for private).
     * `header`: The channel header text.
     * `purpose`: The channel purpose text.
     * `deleted_at`: A timestamp indicating when the channel was deleted (0 if not deleted).
 * **`post`**: Represents a message posted in a channel.
   * `post`:
     * `team`: The name of the team the post belongs to.
     * `channel`: The name of the channel the post was posted in.
     * `user`: The username of the user who posted the message.
     * `type`: The type of post (e.g., "", "system_join_channel", "system_add_to_channel").
     * `message`: The content of the message.
     * `props`: Additional properties of the post.
     * `create_at`: The timestamp when the post was created.
     * `edit_at`: The timestamp when the post was last edited.
     * `reactions`: An array of reactions to the post.
     * `replies`: An array of replies to the post.
     * `attachments`: An array of attachments to the post.
 * **`direct_channel`**: Represents a direct message channel between two users.
   * `direct_channel`:
     * `members`: An array of usernames of the users in the direct channel.
     * `favorited_by`: An array of usernames of users who have favorited the channel.
     * `header`: The channel header text.
 * **`direct_post`**: Represents a message posted in a direct message channel.
   * `direct_post`:
     * `channel_members`: An array of usernames of the users in the direct channel.
     * `user`: The username of the user who posted the message.
     * `type`: The type of post (e.g., "").
     * `message`: The content of the message.
     * `props`: Additional properties of the post.
     * `create_at`: The timestamp when the post was created.
     * `edit_at`: The timestamp when the post was last edited.
     * `flagged_by`: An array of usernames of users who have flagged the post.
     * `reactions`: An array of reactions to the post.
     * `replies`: An array of replies to the post.
     * `attachments`: An array of attachments to the post.
