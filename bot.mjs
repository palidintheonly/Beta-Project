import { Client, GatewayIntentBits, ActivityType, Partials } from 'discord.js';
import express from 'express';
import fs from 'fs';

// Import required modules
import os from 'os';
import { exec } from 'child_process';
import path from 'path';

// Define data directory and file paths for persistent storage
const dataDir = path.resolve('./data');
const modLogsFile = path.join(dataDir, 'modLogs.json');
const auditLogsFile = path.join(dataDir, 'auditLogsHistory.json');
const messageLogsFile = path.join(dataDir, 'messageLogs.json');

// Ensure data directory exists
function ensureDirectoryExists(directory) {
  if (!fs.existsSync(directory)) {
    try {
      fs.mkdirSync(directory, { recursive: true });
      console.log(`Created directory: ${directory}`);
    } catch (err) {
      console.error(`Error creating directory ${directory}:`, err);
      throw err;
    }
  }
}

// Function to load data from a JSON file or create it if it doesn't exist
function loadJSONFile(filePath, defaultValue = []) {
  try {
    // Make sure the directory exists
    ensureDirectoryExists(path.dirname(filePath));
    
    if (fs.existsSync(filePath)) {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      console.log(`Successfully loaded data from ${path.basename(filePath)}`);
      return data;
    } else {
      // File doesn't exist, create it with default value
      fs.writeFileSync(filePath, JSON.stringify(defaultValue, null, 2));
      console.log(`Created new file: ${path.basename(filePath)}`);
      return defaultValue;
    }
  } catch (err) {
    console.error(`Error handling file ${filePath}:`, err);
    return defaultValue; // Return default value in case of error
  }
}

// Initialize logs arrays from files or create new files
console.log('Loading log files from data directory:', dataDir);
let modLogs = loadJSONFile(modLogsFile);
let auditLogsHistory = loadJSONFile(auditLogsFile);
let messageLogs = loadJSONFile(messageLogsFile);

console.log(`Loaded ${modLogs.length} moderation logs, ${auditLogsHistory.length} audit logs, and ${messageLogs.length} message logs`);

// === Bot Configuration ===
const token = 'Redacted';
const clientId = 'Redacted';
const guildId = 'Redacted';

// Create a new Discord client instance
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers
  ],
  partials: [Partials.Message, Partials.Channel]
});

// === In-Memory Log Storage (already loaded from file) ===
const seenAuditLogIds = new Set(auditLogsHistory.map(log => log.id));

// Bot status messages that will rotate every 15 seconds
const statusMessages = [
  { type: ActivityType.Watching, message: 'the management panel at http://prem-eu1.bot-hosting.net:20295' },
  { type: ActivityType.Listening, message: 'server events - check logs in the web panel' },
  { type: ActivityType.Playing, message: 'monitoring your Discord server' }
];
let currentStatusIndex = 0;

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
    1: 'Server Update',
    10: 'Channel Create',
    11: 'Channel Update',
    12: 'Channel Delete',
    13: 'Channel Permission Create',
    14: 'Channel Permission Update',
    15: 'Channel Permission Delete',
    20: 'Member Kick',
    21: 'Member Prune',
    22: 'Member Ban',
    23: 'Member Unban',
    24: 'Member Update',
    25: 'Member Role Update',
    26: 'Member Move',
    27: 'Member Disconnect',
    28: 'Bot Add',
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
    92: 'Sticker Delete',
    100: 'Event Create',
    101: 'Event Update',
    102: 'Event Delete',
    110: 'Thread Create',
    111: 'Thread Update',
    112: 'Thread Delete',
    121: 'Command Permission Update',
    140: 'AutoMod Rule Create',
    141: 'AutoMod Rule Update',
    142: 'AutoMod Rule Delete',
    143: 'AutoMod Block Message',
    144: 'AutoMod Flag Message',
    145: 'AutoMod Timeout User',
    150: 'Monetization Request Created',
    151: 'Monetization Terms Accepted',
    155: 'Voice Channel Status Update',
    160: 'Onboarding Requirement Create',
    161: 'Onboarding Requirement Update',
    162: 'Onboarding Requirement Delete',
    163: 'Onboarding Prompt Create',
    164: 'Onboarding Prompt Update',
    165: 'Onboarding Prompt Delete',
    170: 'Soundboard Sound Create',
    171: 'Soundboard Sound Update',
    172: 'Soundboard Sound Delete'
  };
  // If the action number isn't in our map, return "Unknown Action #X" instead of just the number
  return actionMap[action] || `Unknown Action #${action}`;
}

// Function to update bot status
function updateBotStatus() {
  const status = statusMessages[currentStatusIndex];
  client.user.setActivity(status.message, { type: status.type });
  console.log(`Updated bot status to: ${status.type} ${status.message}`);
  
  // Move to next status message
  currentStatusIndex = (currentStatusIndex + 1) % statusMessages.length;
}

// Get server metrics
function getServerMetrics() {
  return new Promise((resolve) => {
    try {
      // Memory info
      const totalMem = os.totalmem();
      const freeMem = os.freemem();
      const usedMem = totalMem - freeMem;
      
      const metrics = {
        cpu: 0,
        memory: {
          total: (totalMem / (1024 * 1024 * 1024)).toFixed(2), // GB
          free: (freeMem / (1024 * 1024 * 1024)).toFixed(2),
          used: (usedMem / (1024 * 1024 * 1024)).toFixed(2),
          percentUsed: ((usedMem / totalMem) * 100).toFixed(2)
        },
        disk: {
          total: "N/A",
          used: "N/A",
          free: "N/A",
          percentUsed: 0
        },
        uptime: formatUptime(os.uptime() * 1000),
        timestamp: new Date().toLocaleString('en-GB', { hour12: false }),
        load: os.loadavg()
      };
      
      // Try to get CPU usage with exec
      exec("top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\\([0-9.]*\\)%* id.*/\\1/' | awk '{print 100 - $1}'", (cpuError, cpuStdout) => {
        if (!cpuError) {
          metrics.cpu = parseFloat(cpuStdout).toFixed(2);
        } else {
          // Fallback for CPU if command fails
          metrics.cpu = Math.floor(os.loadavg()[0] * 10); // Rough estimate based on load
        }
        
        // Try to get disk info with exec
        exec("df -h / | awk 'NR==2 {print $2,$3,$4,$5}'", (diskError, diskStdout) => {
          if (!diskError && diskStdout) {
            const parts = diskStdout.trim().split(/\s+/);
            if (parts.length >= 4) {
              metrics.disk.total = parts[0];
              metrics.disk.used = parts[1];
              metrics.disk.free = parts[2];
              metrics.disk.percentUsed = parseInt(parts[3].replace('%', ''));
            }
          }
          
          // Return the metrics
          resolve(metrics);
        });
      });
    } catch (error) {
      console.error('Error in getServerMetrics:', error);
      // Return basic metrics if there's an error
      resolve({
        cpu: 0,
        memory: { total: "N/A", used: "N/A", free: "N/A", percentUsed: 0 },
        disk: { total: "N/A", used: "N/A", free: "N/A", percentUsed: 0 },
        uptime: formatUptime(process.uptime() * 1000),
        timestamp: new Date().toLocaleString('en-GB'),
        load: [0, 0, 0]
      });
    }
  });
}

// Function to save data to a JSON file
function saveJSONFile(filePath, data, maxEntries = null) {
  try {
    // Make sure the directory exists
    ensureDirectoryExists(path.dirname(filePath));
    
    // If maxEntries is specified, trim the array
    const trimmedData = maxEntries && Array.isArray(data) 
      ? data.slice(-maxEntries) 
      : data;
    
    // Write data to file
    fs.writeFile(filePath, JSON.stringify(trimmedData, null, 2), (err) => {
      if (err) {
        console.error(`Error writing to ${path.basename(filePath)}:`, err);
      } else {
        console.log(`Successfully saved data to ${path.basename(filePath)}`);
      }
    });
  } catch (err) {
    console.error(`Error handling file ${filePath}:`, err);
  }
}

// Function to save message logs to file
function saveMessageLogs() {
  // Keep only the most recent 1000 messages to prevent the file from growing too large
  saveJSONFile(messageLogsFile, messageLogs, 1000);
}

// === Discord Bot Event Handling ===
client.once('ready', () => {
  console.log(`Bot successfully logged in as ${client.user.tag}!`);
  console.log('Slash commands have been removed as requested');
  
  // Set initial status
  updateBotStatus();
  
  // Start status rotation every 15 seconds
  setInterval(updateBotStatus, 15000);
  console.log('Bot status rotation initialized (15 second intervals)');

  // Start periodic audit log fetching (every 60 seconds)
  setInterval(async () => {
    try {
      console.log('Fetching audit logs...');
      const guild = client.guilds.cache.get(guildId);
      if (!guild) {
        console.warn('Could not find guild, skipping audit log fetch');
        return;
      }
      // Fetch the latest 50 audit log entries
      const auditLogs = await guild.fetchAuditLogs({ limit: 50 });
      let newEntries = false;
      let newEntryCount = 0;
      
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
          newEntryCount++;
        }
      });
      
      if (newEntries) {
        console.log(`Found ${newEntryCount} new audit log entries, saving to file`);
        saveJSONFile(auditLogsFile, auditLogsHistory);
      } else {
        console.log('No new audit log entries found');
      }
    } catch (err) {
      console.error('Error fetching audit logs:', err);
    }
  }, 60000);
  console.log('Audit log fetching initialized (60 second intervals)');
});

// Message editing event handler
client.on('messageUpdate', async (oldMessage, newMessage) => {
  try {
    // Ignore bot messages
    if (newMessage.author && newMessage.author.bot) return;
    
    // Find the existing message in our logs
    const existingMessageIndex = messageLogs.findIndex(msg => msg.id === newMessage.id);
    
    if (existingMessageIndex !== -1) {
      // Update the existing message
      messageLogs[existingMessageIndex].content = newMessage.content;
      messageLogs[existingMessageIndex].status = 'edited';
      messageLogs[existingMessageIndex].editedTimestamp = new Date();
      
      console.log(`Logged edited message from ${messageLogs[existingMessageIndex].author.tag}`);
      
      // Save to file
      saveMessageLogs();
    }
  } catch (error) {
    console.error('Error logging message edit:', error);
  }
});

// Message deletion event handler
client.on('messageDelete', async (message) => {
  try {
    // Ignore bot messages
    if (message.author && message.author.bot) return;
    
    // Find the existing message in our logs
    const existingMessageIndex = messageLogs.findIndex(msg => msg.id === message.id);
    
    if (existingMessageIndex !== -1) {
      // Mark the message as deleted
      messageLogs[existingMessageIndex].status = 'deleted';
      messageLogs[existingMessageIndex].deletedTimestamp = new Date();
      
      console.log(`Logged deleted message from ${messageLogs[existingMessageIndex].author.tag}`);
      
      // Save to file
      saveMessageLogs();
    }
  } catch (error) {
    console.error('Error logging message deletion:', error);
  }
});

// Message logging event handler
client.on('messageCreate', async (message) => {
  try {
    // Ignore bot messages to prevent logging our own responses
    if (message.author.bot) return;
    
    // Get channel information
    const channelName = message.channel.name || 'DirectMessage';
    const channelType = message.channel.type;
    
    // Get author information
    const author = {
      id: message.author.id,
      username: message.author.username,
      tag: message.author.tag
    };
    
    // Get message content
    const content = message.content;
    
    // Check if message has attachments
    const attachments = message.attachments.size > 0 
      ? Array.from(message.attachments.values()).map(a => ({
          name: a.name,
          url: a.url,
          contentType: a.contentType
        }))
      : [];
    
    // Get guild (server) information
    const serverName = message.guild ? message.guild.name : 'Direct Message';
    const serverId = message.guild ? message.guild.id : 'DM';
    
    // Add the message to our logs
    messageLogs.push({
      id: message.id,
      channelId: message.channelId,
      channelName: channelName,
      channelType: channelType,
      author: author,
      content: content,
      attachments: attachments,
      timestamp: message.createdAt,
      serverName: serverName,
      serverId: serverId,
      status: 'posted',
      editedTimestamp: null,
      deletedTimestamp: null
    });
    
    console.log(`Logged message from ${author.tag} in ${channelName}`);
    
    // Save logs periodically (every 10 messages)
    if (messageLogs.length % 10 === 0) {
      saveMessageLogs();
    }
  } catch (error) {
    console.error('Error logging message:', error);
  }
});

// Log in to Discord
console.log('Attempting to log in to Discord...');
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
            margin: 0;
          }
          header {
            background-color: #005f56;
            color: white;
            padding: 10px 20px;
            text-align: center;
            margin-bottom: 20px;
          }
          .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: rgba(255, 255, 255, 0.9);
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
          }
          table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 20px;
          }
          th, td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
          }
          th {
            background-color: #00796b;
            color: white;
          }
          tr:nth-child(even) {
            background-color: #f2f2f2;
          }
          .text-center {
            text-align: center;
          }
          button {
            padding: 10px 20px;
            margin: 5px;
            background-color: #00796b;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.3s;
          }
          button:hover {
            background-color: #005f56;
          }
          .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 5px;
          }
          .status-online {
            background-color: #4CAF50;
          }
          .status-offline {
            background-color: #F44336;
          }
          .refresh-button {
            float: right;
            background-color: #2196F3;
          }
          .refresh-button:hover {
            background-color: #0b7dda;
          }
          .navbar {
            overflow: hidden;
            background-color: #333;
            margin-bottom: 20px;
          }
          .navbar a {
            float: left;
            display: block;
            color: white;
            text-align: center;
            padding: 14px 16px;
            text-decoration: none;
          }
          .navbar a:hover {
            background-color: #ddd;
            color: black;
          }
          .navbar a.active {
            background-color: #00796b;
            color: white;
          }
          .recent-messages-box {
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin: 20px 0;
            max-height: 400px;
            overflow-y: auto;
          }
          
          .recent-message {
            padding: 10px;
            border-bottom: 1px solid #eee;
            margin-bottom: 8px;
            background-color: #ffffff;
            border-radius: 4px;
          }
          
          .recent-message:last-child {
            border-bottom: none;
          }
          
          .recent-message .meta {
            font-size: 0.85em;
            color: #666;
            margin-bottom: 5px;
          }
          
          .recent-message .content {
            margin-top: 5px;
            word-break: break-word;
          }
          
          .message-status {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-left: 5px;
            vertical-align: middle;
            font-size: 0;
          }
          
          .status-posted {
            background-color: #4CAF50;
          }
          
          .status-edited {
            background-color: #FF9800;
          }
          
          .status-deleted {
            background-color: #F44336;
          }
          
          .server-metrics {
            background-color: #fafafa;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin: 20px 0;
          }
          
          .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 10px;
          }
          
          .metric-card {
            background-color: #fff;
            border: 1px solid #eee;
            border-radius: 4px;
            padding: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
          }
          
          .metric-title {
            font-size: 0.9em;
            color: #666;
            margin-bottom: 8px;
          }
          
          .metric-value {
            font-size: 1.2em;
            font-weight: bold;
          }
          
          .metric-timestamp {
            font-size: 0.8em;
            color: #999;
            text-align: right;
            margin-top: 10px;
          }
          
          .progress-bar {
            height: 8px;
            background-color: #e0e0e0;
            border-radius: 4px;
            margin-top: 5px;
          }
          
          .progress-fill {
            height: 100%;
            border-radius: 4px;
            background-color: #4CAF50;
          }
          
          .progress-fill.warning {
            background-color: #FF9800;
          }
          
          .progress-fill.critical {
            background-color: #F44336;
          }
          
          #liveStatus {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
            background-color: #e8f5e9;
            border-left: 5px solid #4CAF50;
          }
          .help-tip {
            background-color: #f5f5f5;
            border-left: 5px solid #2196F3;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
          }
        </style>
        <script>
          // Function to refresh specific content areas without reloading the page
          function refreshStatus() {
            fetch('/status-data')
              .then(response => response.json())
              .then(data => {
                const statusElement = document.getElementById('liveStatus');
                if (statusElement) {
                  let statusHTML = '';
                  if (data.online) {
                    statusHTML = \`<div><span class="status-indicator status-online"></span> Bot is online</div>
                                  <div>Current Activity: \${data.activity}</div>
                                  <div>Uptime: \${data.uptime}</div>
                                  <div>Ping: \${data.ping}ms</div>\`;
                  } else {
                    statusHTML = \`<div><span class="status-indicator status-offline"></span> Bot is offline</div>\`;
                  }
                  statusElement.innerHTML = statusHTML;
                }
              })
              .catch(error => {
                console.error('Error refreshing status:', error);
              });
          }
          
          // Function to refresh recent messages
          function refreshRecentMessages() {
            fetch('/latest-messages')
              .then(response => response.json())
              .then(data => {
                const messagesElement = document.getElementById('recentMessages');
                if (messagesElement) {
                  let messagesHTML = '';
                  
                  if (data.length === 0) {
                    messagesHTML = '<p>No messages recorded yet.</p>';
                  } else {
                    data.forEach(msg => {
                      const time = new Date(msg.timestamp).toLocaleTimeString('en-GB');
                      const date = new Date(msg.timestamp).toLocaleDateString('en-GB');
                      
                      // Determine message status indicator
                      let statusHTML = '';
                      if (msg.status === 'edited') {
                        statusHTML = '<span class="message-status status-edited" title="Edited"></span>';
                      } else if (msg.status === 'deleted') {
                        statusHTML = '<span class="message-status status-deleted" title="Deleted"></span>';
                      } else {
                        statusHTML = '<span class="message-status status-posted" title="Posted"></span>';
                      }
                      
                      // Format content with HTML escaping and line breaks
                      const content = msg.content
                        .replace(/&/g, '&amp;')
                        .replace(/</g, '&lt;')
                        .replace(/>/g, '&gt;')
                        .replace(/\n/g, '<br>');
                      
                      messagesHTML += \`
                        <div class="recent-message">
                          <div class="meta">
                            <strong>\${msg.author.tag}</strong> in 
                            <em>\${msg.serverName} #\${msg.channelName}</em> on 
                            \${date} at \${time}
                            \${statusHTML}
                          </div>
                          <div class="content">\${content}</div>
                        </div>
                      \`;
                    });
                  }
                  
                  messagesElement.innerHTML = messagesHTML;
                }
              })
              .catch(error => {
                console.error('Error refreshing messages:', error);
              });
          }
          
          // Function to refresh server metrics
          function refreshServerMetrics() {
            fetch('/server-metrics')
              .then(response => response.json())
              .then(data => {
                const metricsElement = document.getElementById('serverMetrics');
                if (metricsElement) {
                  // Determine color classes for progress bars
                  const cpuColorClass = data.cpu > 90 ? 'critical' : (data.cpu > 70 ? 'warning' : '');
                  const memColorClass = data.memory.percentUsed > 90 ? 'critical' : (data.memory.percentUsed > 70 ? 'warning' : '');
                  const diskColorClass = data.disk.percentUsed > 90 ? 'critical' : (data.disk.percentUsed > 70 ? 'warning' : '');
                  
                  let metricsHTML = '<h3>VPS Server Metrics</h3>' +
                    '<div class="metrics-grid">' +
                      '<div class="metric-card">' +
                        '<div class="metric-title">CPU Usage</div>' +
                        '<div class="metric-value">' + data.cpu + '%</div>' +
                        '<div class="progress-bar">' +
                          '<div class="progress-fill ' + cpuColorClass + '" style="width: ' + data.cpu + '%"></div>' +
                        '</div>' +
                      '</div>' +
                      
                      '<div class="metric-card">' +
                        '<div class="metric-title">Memory Usage</div>' +
                        '<div class="metric-value">' + data.memory.percentUsed + '% (' + data.memory.used + 'GB / ' + data.memory.total + 'GB)</div>' +
                        '<div class="progress-bar">' +
                          '<div class="progress-fill ' + memColorClass + '" style="width: ' + data.memory.percentUsed + '%"></div>' +
                        '</div>' +
                      '</div>' +
                      
                      '<div class="metric-card">' +
                        '<div class="metric-title">Disk Usage</div>' +
                        '<div class="metric-value">' + data.disk.percentUsed + '% (' + data.disk.used + ' / ' + data.disk.total + ')</div>' +
                        '<div class="progress-bar">' +
                          '<div class="progress-fill ' + diskColorClass + '" style="width: ' + data.disk.percentUsed + '%"></div>' +
                        '</div>' +
                      '</div>' +
                      
                      '<div class="metric-card">' +
                        '<div class="metric-title">System Load (1m, 5m, 15m)</div>' +
                        '<div class="metric-value">' + data.load[0].toFixed(2) + ', ' + data.load[1].toFixed(2) + ', ' + data.load[2].toFixed(2) + '</div>' +
                      '</div>' +
                      
                      '<div class="metric-card">' +
                        '<div class="metric-title">System Uptime</div>' +
                        '<div class="metric-value">' + data.uptime + '</div>' +
                      '</div>' +
                    '</div>' +
                    '<div class="metric-timestamp">Last updated: ' + data.timestamp + '</div>';
                  
                  metricsElement.innerHTML = metricsHTML;
                }
              })
              .catch(error => {
                console.error('Error refreshing server metrics:', error);
                const metricsElement = document.getElementById('serverMetrics');
                if (metricsElement) {
                  metricsElement.innerHTML = '<p>Error loading server metrics. Please try again later.</p>';
                }
              });
          }
          
          // Auto-refresh status every 5 seconds and messages every 10 seconds, metrics every 30 seconds
          window.onload = function() {
            refreshStatus();
            refreshRecentMessages();
            refreshServerMetrics();
            
            setInterval(refreshStatus, 5000);
            setInterval(refreshRecentMessages, 10000);
            setInterval(refreshServerMetrics, 30000);
          };
        </script>
      </head>
      <body>
        <header>
          <h1>Discord Bot Management Panel</h1>
        </header>
        <div class="navbar">
          <a href="/" class="${title === 'Bot CTRL pannel' ? 'active' : ''}">Home</a>
          <a href="/status" class="${title === 'Bot Status' ? 'active' : ''}">Status</a>
          <a href="/logs" class="${title === 'Moderation Logs' ? 'active' : ''}">Mod Logs</a>
          <a href="/auditlogs" class="${title === 'Audit Logs History' ? 'active' : ''}">Audit Logs</a>
          <a href="/messages" class="${title === 'Message Logs' ? 'active' : ''}">Message Logs</a>
        </div>
        <div class="container">
          ${content}
        </div>
      </body>
    </html>
  `;
}

// Home route with management buttons and help tips
app.get('/', (req, res) => {
  const content = `
    <h1>Bot Control Panel</h1>
    <div id="liveStatus"></div>
    
    <div class="help-tip">
      <h3>Getting Started</h3>
      <p>Welcome to the Bot Control Panel! Here you can monitor your bot's status and view moderation logs.</p>
      <p>Use the navigation bar above to access different sections of the panel.</p>
    </div>
    
    <div class="help-tip">
      <h3>Quick Tips</h3>
      <ul>
        <li>The status page shows real-time information about your bot</li>
        <li>Moderation logs show all moderation actions taken</li>
        <li>Audit logs show all Discord server events tracked by the bot</li>
        <li>Message logs provide a searchable history of all server messages</li>
      </ul>
    </div>
    
    <div>
      <button onclick="location.href='/status'">View Detailed Bot Status</button>
      <button onclick="location.href='/logs'">View Moderation Logs</button>
      <button onclick="location.href='/auditlogs'">View Audit Logs History</button>
      <button onclick="location.href='/messages'" style="background-color: #2196F3;">View Message Logs</button>
    </div>
  `;
  res.send(baseHTML("Bot CTRL pannel", content));
});

// API endpoint to get server metrics
app.get('/server-metrics', async (req, res) => {
  try {
    // Get actual server metrics from system
    const metrics = await getServerMetrics();
    res.json(metrics);
  } catch (error) {
    console.error('Error generating metrics:', error);
    res.status(500).json({ error: 'Failed to generate metrics' });
  }
});

// API endpoint to get status data as JSON (for live updates)
app.get('/status-data', (req, res) => {
  let statusData = {
    online: false,
    uptime: '0d 0h 0m 0s',
    ping: 0,
    activity: 'None'
  };
  
  if (client.readyAt) {
    statusData.online = true;
    statusData.uptime = formatUptime(client.uptime);
    statusData.ping = client.ws.ping;
    
    // Get current activity
    const activity = client.user.presence.activities[0];
    if (activity) {
      statusData.activity = `${activity.type} ${activity.name}`;
    }
  }
  
  res.json(statusData);
});

// API endpoint to get latest messages as JSON
app.get('/latest-messages', (req, res) => {
  console.log(`Received request for latest messages. Total messages in log: ${messageLogs.length}`);
  
  // Get the 10 most recent messages
  const latestMessages = [...messageLogs]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 10);
  
  console.log(`Returning ${latestMessages.length} recent messages`);
  
  // Add debug info to response
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(latestMessages));
});

// Bot status route showing uptime and ping with live updates
app.get('/status', (req, res) => {
  let content = `
    <h1>Bot Status</h1>
    <div id="liveStatus"></div>
    
    <div class="server-metrics" id="serverMetrics">
      <p>Loading server metrics...</p>
    </div>
    
    <h2>What These Status Indicators Mean</h2>
    <div class="help-tip">
      <h3>Bot Status Info</h3>
      <p>The status above shows you if your bot is currently online and provides real-time metrics:</p>
      <ul>
        <li><strong>Uptime:</strong> How long the bot has been running since last restart</li>
        <li><strong>Ping:</strong> Response time in milliseconds (lower is better)</li>
        <li><strong>Activity:</strong> The current status message your bot is displaying to users</li>
      </ul>
      <p>The status automatically refreshes every 5 seconds.</p>
    </div>
    
    <button onclick="refreshStatus()" class="refresh-button">Refresh Now</button>
    <button onclick="refreshServerMetrics()" class="refresh-button">Refresh Metrics</button>
  `;
  res.send(baseHTML("Bot Status", content));
});

// Route to display moderation logs
app.get('/logs', (req, res) => {
  let html = `
    <h1>Moderation Logs</h1>
    <div class="help-tip">
      <p>This page displays all moderation actions taken through the bot. Logs are stored even when the bot restarts.</p>
    </div>
    <table>
      <tr>
        <th>Case</th>
        <th>Moderator</th>
        <th>Target</th>
        <th>Reason</th>
        <th>Timestamp</th>
      </tr>
  `;
  
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
  
  html += '</table>';
  res.send(baseHTML("Moderation Logs", html));
});

// Route to display audit logs history
app.get('/auditlogs', (req, res) => {
  let html = `
    <h1>Audit Logs History</h1>
    <div class="help-tip">
      <p>This page shows all server events tracked by Discord's audit log system. The bot checks for new events every 60 seconds.</p>
    </div>
    <table>
      <tr>
        <th>ID</th>
        <th>Action</th>
        <th>Executor</th>
        <th>Target</th>
        <th>Reason</th>
        <th>Created At</th>
      </tr>
  `;
  
  if (auditLogsHistory.length === 0) {
    html += '<tr><td colspan="6">No audit logs available.</td></tr>';
  } else {
    // Sort logs by date (newest first)
    const sortedLogs = [...auditLogsHistory].sort((a, b) => {
      return new Date(b.createdAt) - new Date(a.createdAt);
    });
    
    sortedLogs.forEach(log => {
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
  
  html += '</table>';
  res.send(baseHTML("Audit Logs History", html));
});

// Route to display message logs
app.get('/messages', (req, res) => {
  // Get query parameters for filtering
  const channelFilter = req.query.channel || '';
  const userFilter = req.query.user || '';
  const contentFilter = req.query.content || '';
  const limit = parseInt(req.query.limit) || 100;
  
  let filteredLogs = [...messageLogs];
  
  // Apply filters
  if (channelFilter) {
    filteredLogs = filteredLogs.filter(log => 
      log.channelName.toLowerCase().includes(channelFilter.toLowerCase()) ||
      log.channelId === channelFilter
    );
  }
  
  if (userFilter) {
    filteredLogs = filteredLogs.filter(log => 
      log.author.username.toLowerCase().includes(userFilter.toLowerCase()) ||
      log.author.tag.toLowerCase().includes(userFilter.toLowerCase()) ||
      log.author.id === userFilter
    );
  }
  
  if (contentFilter) {
    filteredLogs = filteredLogs.filter(log => 
      log.content.toLowerCase().includes(contentFilter.toLowerCase())
    );
  }
  
  // Sort by date (newest first)
  filteredLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  
  // Limit number of results
  const paginatedLogs = filteredLogs.slice(0, limit);
  
  let html = `
    <h1>Message Logs</h1>
    
    <h2>Live Message Feed</h2>
    <div class="help-tip">
      <p>This box shows the 10 most recent messages across all channels in real-time. Messages update automatically every 10 seconds.</p>
    </div>
    <div id="recentMessages" class="recent-messages-box">
      <p>Loading recent messages...</p>
    </div>
    
    <div class="help-tip">
      <p>This page displays messages sent in your Discord server. Use the filters to narrow down results.</p>
    </div>
    
    <div class="message-search">
      <form action="/messages" method="get">
        <label for="channel">Channel:</label>
        <input type="text" id="channel" name="channel" placeholder="Channel name or ID" value="${channelFilter}" />
        
        <label for="user">User:</label>
        <input type="text" id="user" name="user" placeholder="Username, tag or ID" value="${userFilter}" />
        
        <label for="content">Content:</label>
        <input type="text" id="content" name="content" placeholder="Message content" value="${contentFilter}" />
        
        <label for="limit">Limit:</label>
        <select id="limit" name="limit">
          <option value="50" ${limit === 50 ? 'selected' : ''}>50</option>
          <option value="100" ${limit === 100 ? 'selected' : ''}>100</option>
          <option value="200" ${limit === 200 ? 'selected' : ''}>200</option>
          <option value="500" ${limit === 500 ? 'selected' : ''}>500</option>
        </select>
        
        <button type="submit">Search</button>
        <button type="button" onclick="location.href='/messages'">Clear</button>
      </form>
    </div>
    
    <div class="log-stats">
      <p>Showing ${paginatedLogs.length} of ${filteredLogs.length} matching messages (total messages: ${messageLogs.length})</p>
    </div>
  `;
  
  if (paginatedLogs.length === 0) {
    html += '<div class="help-tip"><p>No messages found matching your criteria.</p></div>';
  } else {
    // Group messages by date for better readability
    const groupedByDate = {};
    paginatedLogs.forEach(log => {
      const date = new Date(log.timestamp).toLocaleDateString('en-GB');
      if (!groupedByDate[date]) {
        groupedByDate[date] = [];
      }
      groupedByDate[date].push(log);
    });
    
    // Display messages grouped by date
    Object.keys(groupedByDate).forEach(date => {
      html += `<h3>${date}</h3>`;
      
              groupedByDate[date].forEach(log => {
        const timestamp = new Date(log.timestamp).toLocaleTimeString('en-GB');
        const serverName = log.serverName || 'Unknown Server';
        const channelName = log.channelName || 'Unknown Channel';
        
        html += `
          <div class="message-item">
            <strong>${log.author.tag}</strong> in <em>${serverName} #${channelName}</em> at ${timestamp}
            <div class="message-content">${log.content.replace(/\n/g, '<br>')}</div>
        `;
        
        // Display attachments if any
        if (log.attachments && log.attachments.length > 0) {
          html += '<div class="message-attachments">';
          log.attachments.forEach(attachment => {
            html += `<span class="message-attachment">${attachment.name}</span>`;
          });
          html += '</div>';
        }
        
        // Display status if available
        if (log.status) {
          let statusClass = '';
          if (log.status === 'edited') {
            statusClass = 'status-edited';
          } else if (log.status === 'deleted') {
            statusClass = 'status-deleted';
          } else {
            statusClass = 'status-posted';
          }
          
          html += `<div class="message-meta">
            Message ID: ${log.id} | Channel ID: ${log.channelId} | 
            <span class="message-status ${statusClass}">${log.status.toUpperCase()}</span>
          </div>`;
        } else {
          html += `<div class="message-meta">
            Message ID: ${log.id} | Channel ID: ${log.channelId}
          </div>`;
        }
        
        html += `
          </div>
          <hr>
        `;
      });
    });
  }
  
  // Add recent messages section at the bottom
  html += `
    <h2>Live Message Feed</h2>
    <div class="help-tip">
      <p>This box shows the 10 most recent messages across all channels in real-time. Messages update automatically every 10 seconds.</p>
    </div>
    <div id="recentMessages" class="recent-messages-box">
      <p>Loading recent messages...</p>
    </div>
    
    <script>
      // Call this function when the page loads
      document.addEventListener('DOMContentLoaded', function() {
        refreshRecentMessages();
        // Set up interval to refresh every 10 seconds
        setInterval(refreshRecentMessages, 10000);
      });
      
      // Function to refresh recent messages
      function refreshRecentMessages() {
        console.log("Refreshing recent messages...");
        fetch('/latest-messages')
          .then(response => response.json())
          .then(data => {
            console.log("Received data:", data);
            const messagesElement = document.getElementById('recentMessages');
            if (messagesElement) {
              let messagesHTML = '';
              
              if (data.length === 0) {
                messagesHTML = '<p>No messages recorded yet.</p>';
              } else {
                data.forEach(msg => {
                  const time = new Date(msg.timestamp).toLocaleTimeString('en-GB');
                  const date = new Date(msg.timestamp).toLocaleDateString('en-GB');
                  const serverName = msg.serverName || 'Unknown Server';
                  
                  // Determine message status indicator as dots
                  let statusHTML = '';
                  if (msg.status === 'edited') {
                    statusHTML = '<span class="message-status status-edited" title="Edited"></span>';
                  } else if (msg.status === 'deleted') {
                    statusHTML = '<span class="message-status status-deleted" title="Deleted"></span>';
                  } else {
                    statusHTML = '<span class="message-status status-posted" title="Posted"></span>';
                  }
                  
                  // Format content with HTML escaping and line breaks
                  // Truncate message to 20 characters with ellipsis
                  const content = msg.content
                    ? (msg.content.length > 20
                        ? msg.content.substring(0, 20).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') + '...'
                        : msg.content.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'))
                    : '';
                  
                  messagesHTML += \`
                    <div class="recent-message">
                      <div class="meta">
                        <strong>\${msg.author ? msg.author.tag : 'Unknown User'}</strong> in 
                        <em>\${serverName} #\${msg.channelName}</em> on 
                        \${date} at \${time}
                        \${statusHTML}
                      </div>
                      <div class="content">\${content}</div>
                    </div>
                  \`;
                });
              }
              
              messagesElement.innerHTML = messagesHTML;
              console.log("Updated recent messages display");
            }
          })
          .catch(error => {
            console.error('Error refreshing messages:', error);
            document.getElementById('recentMessages').innerHTML = 
              '<p>Error loading messages. Please check the console for details.</p>';
          });
      }
    </script>
  `;
  
  res.send(baseHTML("Message Logs", html));
});

// Start the web server on all network interfaces
app.listen(port, '0.0.0.0', () => {
  console.log(`Web management interface running at http://prem-eu1.bot-hosting.net:${port}`);
  console.log('Management panel is now "live" with auto-refreshing status');
  console.log(`Using data directory: ${dataDir}`);
  
  // Set up periodic saves for all data
  setInterval(() => {
    saveJSONFile(modLogsFile, modLogs);
    saveJSONFile(auditLogsFile, auditLogsHistory, 5000); // Limit audit logs to 5000 entries
    saveMessageLogs(); // Already handles limiting to 1000 entries
    console.log('Performed automatic data backup');
  }, 300000); // Save all data every 5 minutes
});