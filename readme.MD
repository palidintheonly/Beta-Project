# 🐒 MonkeyBytes Authentication Bot

[![Discord](https://img.shields.io/discord/1092952464766021632?color=7289da&logo=discord&logoColor=white&label=Discord)](https://discord.gg/yp57R5s7gq)
[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)](https://github.com/palidintheonly/Beta-Project)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/palidintheonly/Beta-Project/blob/main/LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-14.x-43853d.svg?logo=node.js&logoColor=white)](https://nodejs.org)
[![Status](https://img.shields.io/badge/status-active-success.svg)](https://github.com/palidintheonly/Beta-Project)

A Discord bot for managing user authentication and verification in the MonkeyBytes community server. This bot provides a seamless verification experience with a custom medieval/royal court theme.

## ✨ Features

### 🔐 Authentication System
- OAuth2 Discord authentication flow
- Web-based verification portal
- Staff approval queue for new verification requests
- Role assignment for verified members
- Complete tracking of verified, pending, and deauthorized users

### 🛡️ Moderation Tools
- Deauthorize problematic users
- Mark messages as rule violations
- Track user statistics
- Resource collection system for saving valuable content

### 👨‍💻 Member Commands
- `/help` - Shows available commands and how to use them
- `/verify` - Starts the verification process
- `/resources` - Shows available coding resources
- `/roles` - Explains server roles and how to get them
- `/report` - Report issues to staff

### 👑 Staff Commands
- Context menu: `Verify Member` - Manually verify a user
- Context menu: `Deauthorize Member` - Remove verification from a user
- Context menu: `View User Stats` - See details about a user's status
- Context menu: `Mark as Rule Violation` - Flag a message as breaking rules
- Context menu: `Add to Resources` - Save a message to resources channel
- `/restart` - Safely restart the bot
- `/stop` - Safely shut down the bot

### 📊 Monitoring
- Uptime tracking and reporting
- Memory usage monitoring
- Service heartbeat messages
- Downtime detection

## 🚀 Installation

1. Clone this repository
```bash
git clone https://github.com/palidintheonly/Beta-Project.git
cd Beta-Project
```

2. Install dependencies
```bash
npm install discord.js express express-session passport passport-discord fs path
```

3. Edit the configuration in the source code:
```javascript
// Find and edit the config object in monkeybytes-auth-bot.mjs
const config = {
  clientId: 'Get your own Discord client ID',
  clientSecret: 'Get your own Discord client secret',
  token: 'Get your own Discord bot token',
  // Other configuration values...
};
```

4. Start the bot
```bash
node monkeybytes-auth-bot.mjs
```

## ⚙️ Setting Up Discord Application

1. Create a new application at the [Discord Developer Portal](https://discord.com/developers/applications)

2. Under the "Bot" tab, create a bot and enable:
   - Presence Intent
   - Server Members Intent
   - Message Content Intent

3. Under "OAuth2" > "URL Generator":
   - Select scopes: `bot`, `applications.commands`
   - Select permissions: `Manage Roles`, `Send Messages`, `Read Messages/View Channels`, `Add Reactions`
   - Copy the generated URL and use it to invite the bot to your server

4. Configure redirect URLs:
   - Add your OAuth2 redirect URL (e.g., `http://your-server-url:20295/auth/callback`)

## 📝 Required Channels

The bot needs these channels to be set up (IDs configured directly in the code):
- Verification category
- Verification channel (where users click to verify)
- Staff approval channel (for approval requests)
- Log channel (for activity logs)
- Resources channel (for saved resources)
- Heartbeat channel (for service status updates)
- Uptime logs channel (for uptime reporting)

## 💾 Database

The bot uses a file-based database system storing data in:
- `./monkey-verified-users.json` - User verification data
- `./monkey-uptime-history.json` - Uptime tracking

## 🎨 Customization

You can customize the bot's appearance and messages by editing these variables in the configuration section of the code:

```javascript
const config = {
  // ... other config
  embedColor: '#3eff06',
  embedFooter: '© MonkeyBytes Tech | The Royal Court',
  welcomeMessage: "🎉 Welcome message...",
  verificationMessage: "To join the MonkeyBytes court...",
  // ... other config
};
```

## 🏭 Running in Production

For production use, it's recommended to use a process manager like PM2:

```bash
# Install PM2
npm install -g pm2

# Start the bot with PM2
pm2 start monkeybytes-auth-bot.mjs --name monkeybytes-auth

# Make it start on system boot
pm2 startup
pm2 save
```

Staff can also use the `/restart` and `/stop` commands within Discord to manage the bot's lifecycle.

## 🔒 Security Considerations

- The bot implements basic security headers for the web interface
- Session management with secure cookies
- IP filtering for sensitive endpoints
- Role-based access control for staff commands

**⚠️ Important:** Make sure to get your own Discord credentials before deploying.

## 📄 License

[MIT License](https://github.com/palidintheonly/Beta-Project/blob/main/LICENSE)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request to the [GitHub repository](https://github.com/palidintheonly/Beta-Project).

## 🆘 Support

For issues or questions, please open an issue on the [GitHub repository](https://github.com/palidintheonly/Beta-Project) or join our Discord community:

[![Discord](https://img.shields.io/discord/1092952464766021632?color=7289da&logo=discord&logoColor=white&label=Discord)](https://discord.gg/yp57R5s7gq)

<div align="center">
  <a href="https://discord.gg/yp57R5s7gq">
    <img src="https://discordapp.com/api/guilds/1092952464766021632/widget.png?style=banner4" alt="Join the MonkeyBytes Discord community">
  </a>
</div>