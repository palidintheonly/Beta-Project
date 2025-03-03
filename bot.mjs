import { Client, GatewayIntentBits, Routes } from 'discord.js';
import { REST } from '@discordjs/rest';
import express from 'express';
import fs from 'fs';

// File paths for persistent storage
const modLogsFile = './modLogs.json';
const auditLogsFile = './auditLogsHistory.json';

// Initialize logs arrays from file if exists, otherwise create new files
let modLogs = [];
let auditLogsHistory = [];
if (fs.existsSync(modLogsFile)) {
  try {
    modLogs = JSON.parse(fs.readFileSync(modLogsFile, 'utf8'));
  } catch (err) {
    console.error('Error reading modLogs file:', err);
    modLogs = [];
  }
} else {
  fs.writeFileSync(modLogsFile, JSON.stringify([]));
}
if (fs.existsSync(auditLogsFile)) {
  try {
    auditLogsHistory = JSON.parse(fs.readFileSync(auditLogsFile, 'utf8'));
  } catch (err) {
    console.error('Error reading auditLogs file:', err);
    auditLogsHistory = [];
  }
} else {
  fs.writeFileSync(auditLogsFile, JSON.stringify([]));
}

// === Bot Configuration ===
const token = 'MTM0NjE5Nzk2MDUxMzQyNTQ4OQ.GNhson.BESZ54nca8mc-tKIrUNh5qxR6J-2c9XR7ooKCk';
const clientId = '1346197960513425489';
const guildId = '1269949849810501643';

// Create a new Discord client instance
const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages],
});

// === In-Memory Log Storage (already loaded from file) ===
const seenAuditLogIds = new Set(auditLogsHistory.map(log => log.id));

// === Slash Commands (Hard-Coded) ===
const commands = [
  {
    name: 'ban',
    description: 'Ban a user',
    options: [
      {
        name: 'user',
        type: 6, // USER type
        description: 'User to ban',
        required: true,
      },
      {
        name: 'reason',
        type: 3, // STRING type
        description: 'Reason for ban',
        required: false,
      },
    ],
  },
  {
    name: 'kick',
    description: 'Kick a user',
    options: [
      {
        name: 'user',
        type: 6, // USER type
        description: 'User to kick',
        required: true,
      },
      {
        name: 'reason',
        type: 3, // STRING type
        description: 'Reason for kick',
        required: false,
      },
    ],
  },
];

// Register slash commands using Discord's REST API
const rest = new REST({ version: '10' }).setToken(token);
(async () => {
  try {
    console.log('Refreshing application (/) commands...');
    await rest.put(
      Routes.applicationGuildCommands(clientId, guildId),
      { body: commands }
    );
    console.log('Slash commands refreshed.');
  } catch (error) {
    console.error('Error registering commands:', error);
  }
})();

// Helper function to format uptime in a UK style (days, hours, minutes, seconds)
function formatUptime(ms) {
  let seconds = Math.floor(ms / 1000);
  let minutes = Math.floor(seconds / 60);
  let hours = Math.floor(minutes / 60);
  let days = Math.floor(hours / 24);
  seconds = seconds % 60;
  minutes = minutes % 60;
  hours = hours % 24;
  return `${days}d ${hours}h ${minutes}m ${seconds}s`;
}

// Helper function to convert audit log action numbers to human‑readable strings
function formatAuditAction(action) {
  const actionMap = {
    10: 'Channel Create',
    11: 'Channel Update',
    12: 'Channel Delete',
    13: 'Overwrite Create',
    14: 'Overwrite Update',
    15: 'Overwrite Delete',
    20: 'Member Kick',
    21: 'Member Prune',
    22: 'Ban',
    23: 'Unban',
    24: 'Member Update',
    30: 'Role Create',
    31: 'Role Update',
    32: 'Role Delete',
    40: 'Invite Create',
    41: 'Invite Update',
    42: 'Invite Delete',
    50: 'Webhook Create',
    51: 'Webhook Update',
    52: 'Webhook Delete',
    60: 'Emoji Create',
    61: 'Emoji Update',
    62: 'Emoji Delete',
    72: 'Message Delete',
    73: 'Message Bulk Delete',
    74: 'Message Pin',
    75: 'Message Unpin',
    80: 'Integration Create',
    81: 'Integration Update',
    82: 'Integration Delete',
    83: 'Stage Instance Create',
    84: 'Stage Instance Update',
    85: 'Stage Instance Delete',
    90: 'Sticker Create',
    91: 'Sticker Update',
    92: 'Sticker Delete'
  };
  return actionMap[action] || action;
}

// === Discord Bot Event Handling ===
client.once('ready', () => {
  console.log(`Logged in as ${client.user.tag}!`);

  // Start periodic audit log fetching (every 60 seconds)
  setInterval(async () => {
    try {
      const guild = client.guilds.cache.get(guildId);
      if (!guild) return;
      // Fetch the latest 50 audit log entries
      const auditLogs = await guild.fetchAuditLogs({ limit: 50 });
      let newEntries = false;
      auditLogs.entries.forEach(entry => {
        if (!seenAuditLogIds.has(entry.id)) {
          seenAuditLogIds.add(entry.id);
          auditLogsHistory.push({
            id: entry.id,
            action: entry.action,
            executor: entry.executor ? entry.executor.tag : 'Unknown',
            target: entry.target ? (entry.target.tag || entry.target.id) : 'Unknown',
            reason: entry.reason || 'No reason provided',
            createdAt: entry.createdAt,
          });
          newEntries = true;
        }
      });
      if (newEntries) {
        fs.writeFile(auditLogsFile, JSON.stringify(auditLogsHistory, null, 2), (err) => {
          if (err) console.error('Error writing auditLogs file:', err);
        });
      }
    } catch (err) {
      console.error('Error fetching audit logs:', err);
    }
  }, 60000);
});

client.on('interactionCreate', async interaction => {
  if (!interaction.isCommand()) return;

  const { commandName } = interaction;
  const timestamp = new Date();

  if (commandName === 'ban') {
    const targetUser = interaction.options.getUser('user');
    const reason = interaction.options.getString('reason') || 'No reason provided';
    modLogs.push({
      case: 'ban',
      moderator: interaction.user.tag,
      target: targetUser.tag,
      reason,
      timestamp,
    });
    fs.writeFile(modLogsFile, JSON.stringify(modLogs, null, 2), (err) => {
      if (err) console.error('Error writing modLogs file:', err);
    });
    await interaction.reply(`User ${targetUser.tag} would be banned for: ${reason}`);
  } else if (commandName === 'kick') {
    const targetUser = interaction.options.getUser('user');
    const reason = interaction.options.getString('reason') || 'No reason provided';
    modLogs.push({
      case: 'kick',
      moderator: interaction.user.tag,
      target: targetUser.tag,
      reason,
      timestamp,
    });
    fs.writeFile(modLogsFile, JSON.stringify(modLogs, null, 2), (err) => {
      if (err) console.error('Error writing modLogs file:', err);
    });
    await interaction.reply(`User ${targetUser.tag} would be kicked for: ${reason}`);
  }
});

// Log in to Discord
client.login(token);

// === Web Management Interface using Express ===
const app = express();
const port = 20295;

// Base HTML template with light blue transparent background and button styling
function baseHTML(title, content) {
  return `
    <!DOCTYPE html>
    <html>
      <head>
        <title>${title}</title>
        <style>
          body {
            background-color: rgba(173, 216, 230, 0.5);
            font-family: Arial, sans-serif;
            padding: 20px;
          }
          table {
            border-collapse: collapse;
            width: 100%;
          }
          th, td {
            border: 1px solid #ccc;
            padding: 8px;
            text-align: left;
          }
          th {
            background-color: #00796b;
            color: #fff;
          }
          button {
            padding: 10px 20px;
            margin: 5px;
            background-color: #00796b;
            color: #fff;
            border: none;
            cursor: pointer;
          }
          button:hover {
            background-color: #005f56;
          }
        </style>
      </head>
      <body>
        ${content}
      </body>
    </html>
  `;
}

// Home route with management buttons (title changed to "Bot CTRL pannel")
app.get('/', (req, res) => {
  const content = `
    <h1>Bot CTRL pannel</h1>
    <button onclick="location.href='/status'">Bot Status</button>
    <button onclick="location.href='/reload-commands'">Reload Slash Commands</button>
    <button onclick="location.href='/logs'">View Moderation Logs</button>
    <button onclick="location.href='/auditlogs'">View Audit Logs History</button>
  `;
  res.send(baseHTML("Bot CTRL pannel", content));
});

// Bot status route showing uptime and ping (UK format)
app.get('/status', (req, res) => {
  let content = '';
  if (client.readyAt) {
    const uptimeFormatted = formatUptime(client.uptime);
    const ping = client.ws.ping;
    content = `<p>Bot is live. Uptime: ${uptimeFormatted}. Ping: ${ping}ms</p>`;
  } else {
    content = `<p>Bot is offline.</p>`;
  }
  res.send(baseHTML("Bot Status", content));
});

// Route to reload slash commands (hard-coded)
app.get('/reload-commands', async (req, res) => {
  try {
    await rest.put(
      Routes.applicationGuildCommands(clientId, guildId),
      { body: commands }
    );
    res.send(baseHTML("Reload Commands", `<p>Slash commands reloaded successfully.</p><button onclick="location.href='/'">Back</button>`));
  } catch (error) {
    console.error('Error reloading commands:', error);
    res.send(baseHTML("Reload Commands", `<p>Error reloading slash commands.</p><button onclick="location.href='/'">Back</button>`));
  }
});

// Route to display moderation logs
app.get('/logs', (req, res) => {
  let html = '<h1>Moderation Logs</h1><table><tr><th>Case</th><th>Moderator</th><th>Target</th><th>Reason</th><th>Timestamp</th></tr>';
  if (modLogs.length === 0) {
    html += '<tr><td colspan="5">No moderation logs available.</td></tr>';
  } else {
    modLogs.forEach(log => {
      html += `<tr>
        <td>${log.case}</td>
        <td>${log.moderator}</td>
        <td>${log.target}</td>
        <td>${log.reason}</td>
        <td>${new Date(log.timestamp).toLocaleString('en-GB')}</td>
      </tr>`;
    });
  }
  html += '</table><button onclick="location.href=\'/\'">Back</button>';
  res.send(baseHTML("Moderation Logs", html));
});

// Route to display audit logs history
app.get('/auditlogs', (req, res) => {
  let html = '<h1>Audit Logs History</h1><table><tr><th>ID</th><th>Action</th><th>Executor</th><th>Target</th><th>Reason</th><th>Created At</th></tr>';
  if (auditLogsHistory.length === 0) {
    html += '<tr><td colspan="6">No audit logs available.</td></tr>';
  } else {
    auditLogsHistory.forEach(log => {
      html += `<tr>
        <td>${log.id}</td>
        <td>${formatAuditAction(log.action)}</td>
        <td>${log.executor}</td>
        <td>${log.target}</td>
        <td>${log.reason}</td>
        <td>${new Date(log.createdAt).toLocaleString('en-GB')}</td>
      </tr>`;
    });
  }
  html += '</table><button onclick="location.href=\'/\'">Back</button>';
  res.send(baseHTML("Audit Logs History", html));
});

// Start the web server on all network interfaces
app.listen(port, '0.0.0.0', () => {
  console.log(`Web management interface running at http://prem-eu1.bot-hosting.net:${port}`);
});
