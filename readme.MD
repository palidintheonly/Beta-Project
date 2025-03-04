# ByteTracker - Discord Monitoring Bot 🤖

![Version](https://img.shields.io/badge/version-2.0.2-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A comprehensive Discord monitoring bot that captures server activity with a real-time web dashboard. ByteTracker logs messages, tracks audit events, and monitors server performance metrics.

## 🔍 Key Features

- **💬 Message Logging:** Captures all messages with edit/delete history and attachment tracking
- **📝 Audit Log Monitoring:** Records server events (member joins, channel creation, role changes, etc.)
- **📊 Server Performance:** Monitors CPU, memory, and disk usage of your host server
- **🌐 Real-Time Dashboard:** Web interface with live updates for all logs and metrics
- **💾 Persistent Storage:** Stores data in JSON files that survive bot restarts
- **🔄 Status Rotation:** Customizable rotating status messages

## ⚙️ Requirements

- Node.js v16.0.0 or higher
- Discord.js v14.0.0
- Discord bot token with appropriate permissions
- Server with ability to expose HTTP port for web dashboard

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/monkeybytes/bytetracker.git
cd bytetracker
```

2. Install required dependencies:
```bash
npm install discord.js express fs os child_process path
```

3. Create a `.env` file in the root directory:
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

## ⚠️ Security Note

The bot.mjs file contains a placeholder Discord token. Before deploying:

1. Change the redacted token to your new Discord bot token (this must remain hardcoded)
2. Secure your web dashboard with a reverse proxy for authentication

## 🛠️ Configuration Options

Edit bot.mjs to customize these settings:

```javascript
// Web dashboard port
const port = process.env.PORT || 20295;

// Status rotation interval (milliseconds)
setInterval(updateBotStatus, 15000); 

// Data backup interval (milliseconds)
setInterval(() => {
  // Backup logic
}, 300000); // 5 minutes

// Status messages
const statusMessages = [
  { type: ActivityType.Custom, message: "Your custom message" },
  // Add more status messages here
];
```

## 🖥️ Using the Web Dashboard

Access your dashboard at `http://your-server-ip:PORT`

Where PORT is the value you set in your configuration (default is 20295, but you should set this to your own preferred port - some hosting environments may not require specifying a port at all)

### Dashboard Sections:

- **🏠 Home:** Overview and quick navigation
- **📊 Status:** Real-time bot status and server metrics
- **⏱️ Uptime:** Detailed bot uptime statistics
- **🔨 Mod Logs:** View moderation actions
- **📜 Audit Logs:** Server event history
- **💬 Message Logs:** Searchable message history with filters and live feed

### Auto-Refresh Features:

- Bot status: Updates every 5 seconds
- Recent messages: Updates every 10 seconds
- Server metrics: Updates every 30 seconds

## 💾 Data Storage

Logs are stored in the `./data` directory:

- `modLogs.json` - Moderation actions
- `auditLogsHistory.json` - Server audit logs (limited to 5000 entries)
- `messageLogs.json` - Message history (limited to 1000 entries)
- `uptime.json` - Bot uptime statistics
- `status.json` - Current bot status information

Data is automatically backed up every 5 minutes.

## 🛡️ Privacy Considerations

- Message logs contain the full content of all messages
- User IDs and usernames are stored in the logs
- Consider GDPR implications if deployed in regions where it applies

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b new-feature`
3. Commit your changes: `git commit -am 'Add new feature'`
4. Push to the branch: `git push origin new-feature`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Credits

Developed by [MonkeyBytes](https://github.com/palidintheonly)

---

© 2025 MonkeyBytes. All rights reserved.