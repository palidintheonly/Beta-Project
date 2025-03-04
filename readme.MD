# ByteTracker - Discord Monitoring Bot by MonkeyBytes

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A comprehensive Discord bot for monitoring and logging server activities with a web-based management interface. ByteTracker captures messages, audit logs, and server metrics in real-time.

![ByteTracker Dashboard](https://via.placeholder.com/800x400?text=ByteTracker+Dashboard)

## Features

- **Message Logging:** Tracks all messages with editing and deletion history
- **Audit Log Monitoring:** Tracks server events like member joins, channel creation, role changes
- **Server Metrics:** Monitors CPU, memory, and disk usage of the hosting server
- **Web Dashboard:** Easy-to-use web interface to view all logs and metrics
- **Data Persistence:** Stores logs in JSON files for reliability across restarts
- **Auto-rotating Status:** Displays useful information as bot status messages

## Requirements

- Node.js v16.0.0 or higher
- Discord.js v14.0.0 or higher
- A Discord bot token and application
- Server permissions for reading messages and audit logs

## Installation

1. Clone the repository:
```bash
git clone https://github.com/monkeybytes/bytetracker.git
cd bytetracker
```

2. Install dependencies:
```bash
npm install discord.js express fs os child_process path
```

3. Create a `.env` file in the root directory with your bot token:
```
DISCORD_TOKEN=your_bot_token_here
CLIENT_ID=your_client_id_here
GUILD_ID=your_guild_id_here
PORT=20295
```

4. Start the bot:
```bash
node bot.mjs
```

## Configuration

Edit the configuration in the bot.mjs file:

```javascript
// Change the port for the web interface
const port = process.env.PORT || 20295;

// Change status rotation interval (in milliseconds)
setInterval(updateBotStatus, 15000); 

// Change automatic backup interval (in milliseconds)
setInterval(() => {
  // File backup logic
}, 300000); // 5 minutes
```

## Usage

### Web Dashboard

Access the web dashboard at `http://your-server-ip:20295`

The dashboard includes:
- **Home:** Overview of bot status and quick navigation
- **Status:** Real-time bot status and server metrics
- **Mod Logs:** View moderation actions taken
- **Audit Logs:** History of server changes and actions
- **Message Logs:** Searchable log of all messages with filters

### Bot Features

- **Message Logging:** Automatically tracks all messages, edits, and deletions
- **Metric Monitoring:** Automatically collects server performance metrics
- **Audit Log Tracking:** Periodically checks for new audit log entries

## Data Storage

Logs are stored in the `./data` directory:
- `modLogs.json` - Moderation actions
- `auditLogsHistory.json` - Server audit logs
- `messageLogs.json` - Message history

Data is automatically backed up every 5 minutes and limited to prevent excessive file growth:
- Message logs: Limited to 1000 entries
- Audit logs: Limited to 5000 entries

## Security Notes

- The web interface has no built-in authentication - secure it with a reverse proxy
- Bot token should be stored in environment variables, not hardcoded
- Logs contain message content - ensure GDPR compliance if applicable

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b new-feature`
3. Commit your changes: `git commit -am 'Add new feature'`
4. Push to the branch: `git push origin new-feature`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Credits

Developed by [MonkeyBytes](https://github.com/monkeybytes)

---

© 2025 MonkeyBytes. All rights reserved.