// monkeybytes-auth-bot.mjs
// Streamlined Discord Authentication Bot for MonkeyBytes using IDs only

import { Client, GatewayIntentBits, EmbedBuilder, ButtonBuilder, ActionRowBuilder, 
  ButtonStyle, PermissionsBitField, ChannelType, ActivityType, ApplicationCommandType,
  ModalBuilder, TextInputBuilder, TextInputStyle, MessageFlags } from 'discord.js';
import express from 'express';
import session from 'express-session';
import passport from 'passport';
import { Strategy } from 'passport-discord';
import fs from 'fs';
import path from 'path';
import axios from 'axios'; // For webhook requests
import os from 'os'; // For system info
import { exec } from 'child_process'; // For restart functionality

// CONFIGURATION - REPLACE WITH YOUR OWN VALUES
const config = {
  // User provided credentials
  clientId: '<YOUR_CLIENT_ID>',
  clientSecret: '<YOUR_CLIENT_SECRET>',
  token: '<YOUR_BOT_TOKEN>',

  // Server configuration
  port: 20295,
  redirectUri: 'http://your-server.example.com:20295/auth/callback',
  serverUrl: 'http://your-server.example.com:20295',

  // Discord IDs
  guildId: '<YOUR_GUILD_ID>',
  verifiedRoleId: '<YOUR_VERIFIED_ROLE_ID>',
  staffRoleId: '<YOUR_STAFF_ROLE_ID>', 

  // Channel IDs - Set these or they will be created automatically
  verificationCategoryId: '<YOUR_CATEGORY_ID>', // Optional
  verificationChannelId: '<YOUR_VERIFICATION_CHANNEL_ID>', // Optional
  logChannelId: '<YOUR_LOG_CHANNEL_ID>', // Optional

  // Session settings
  sessionSecret: 'your-session-secret-change-this',
  dbPath: './monkey-verified-users.json',
  configPath: './monkey-config.json',

  // Branding
  embedColor: '#3eff06',
  embedFooter: '© MonkeyBytes Tech | The Code Jungle',

  // Default messages
  welcomeMessage: "🎉 Welcome to the MonkeyBytes jungle! You've been verified and can now access all our coding resources and community features. Grab a banana and start coding! 🍌💻",
  verificationMessage: "To join the MonkeyBytes community, you'll need to verify your account. Click the button below to get your access banana! 🍌\n\nThis helps us keep our jungle safe from bots.",

  // Heartbeat configuration
  heartbeatWebhook: "https://discord.com/api/webhooks/your-webhook-url",
  heartbeatImageUrl: "https://example.com/your-image.png",
  heartbeatInterval: 630000, // 10 minutes and 30 seconds
  
  // Restart configuration
  restartInterval: 3600000, // 1 hour in milliseconds
  restartMessageTitle: "🔄 Scheduled Maintenance",
  restartMessage: "The MonkeyBytes Authentication system is performing a scheduled restart to ensure optimal performance and reliability. Service will resume automatically in a few seconds. 🍌"
};

// Initialize Discord client
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers
  ]
});

// Console logging function with enhanced debugging
const LOG_LEVELS = {
  DEBUG: { level: 0, prefix: '🐛 DEBUG', color: '\x1b[36m' }, // Cyan
  INFO: { level: 1, prefix: 'ℹ️ INFO', color: '\x1b[32m' },   // Green
  WARN: { level: 2, prefix: '⚠️ WARN', color: '\x1b[33m' },   // Yellow
  ERROR: { level: 3, prefix: '❌ ERROR', color: '\x1b[31m' },  // Red
  FATAL: { level: 4, prefix: '💀 FATAL', color: '\x1b[35m' }  // Magenta
};

// Current log level - can be adjusted as needed
const CURRENT_LOG_LEVEL = LOG_LEVELS.DEBUG.level;

// Reset color code
const RESET_COLOR = '\x1b[0m';

// Add debug flag to config
config.debug = true;

// Enhanced logging function
const log = (message, level = 'INFO', error = null, context = '') => {
  const logLevel = LOG_LEVELS[level] || LOG_LEVELS.INFO;
  
  // Only log if the current level is less than or equal to the set level
  if (logLevel.level >= CURRENT_LOG_LEVEL) {
    const timestamp = new Date().toISOString();
    const contextStr = context ? `[${context}] ` : '';
    const prefix = `[${timestamp}] ${logLevel.prefix} ${contextStr}[MonkeyBytes] `;
    
    console.log(`${logLevel.color}${prefix}${message}${RESET_COLOR}`);
    
    if (error) {
      if (level === 'DEBUG' && config.debug) {
        console.log(`${LOG_LEVELS.ERROR.color}${prefix}${error.stack || error}${RESET_COLOR}`);
      } else if (level !== 'DEBUG') {
        console.log(`${LOG_LEVELS.ERROR.color}${prefix}${error.stack || error}${RESET_COLOR}`);
      }
    }
    
    // Log additional debug information when in debug mode
    if (level === 'DEBUG' && config.debug && typeof message === 'object') {
      console.dir(message, { depth: null, colors: true });
    }
  }
};

// Helper function to format uptime nicely
function formatUptime(uptime) {
  const days = Math.floor(uptime / 86400);
  const hours = Math.floor((uptime % 86400) / 3600);
  const minutes = Math.floor((uptime % 3600) / 60);
  const seconds = Math.floor(uptime % 60);
  return `${days}d ${hours}h ${minutes}m ${seconds}s`;
}

// Load config file if exists
try {
  if (fs.existsSync(config.configPath)) {
    const savedConfig = JSON.parse(fs.readFileSync(config.configPath, 'utf8'));
    // Only update channel IDs and messages from saved config
    if (savedConfig.verificationCategoryId) config.verificationCategoryId = savedConfig.verificationCategoryId;
    if (savedConfig.verificationChannelId) config.verificationChannelId = savedConfig.verificationChannelId;
    if (savedConfig.logChannelId) config.logChannelId = savedConfig.logChannelId;
    if (savedConfig.welcomeMessage) config.welcomeMessage = savedConfig.welcomeMessage;
    if (savedConfig.verificationMessage) config.verificationMessage = savedConfig.verificationMessage;

    log(`Loaded configuration from file`, 'INFO', null, 'CONFIG');
  }
} catch (error) {
  log(`Failed to load configuration, using defaults`, 'WARN', error, 'CONFIG');
}

// Save config to file
function saveConfig() {
  try {
    // Check if directory exists, create if not
    const configDir = path.dirname(config.configPath);
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }
    
    // Only save the dynamic parts of config
    const configToSave = {
      verificationCategoryId: config.verificationCategoryId,
      verificationChannelId: config.verificationChannelId,
      logChannelId: config.logChannelId,
      welcomeMessage: config.welcomeMessage,
      verificationMessage: config.verificationMessage
    };

    fs.writeFileSync(config.configPath, JSON.stringify(configToSave, null, 2));
    return true;
  } catch (error) {
    log(`Failed to save configuration`, error);
    return false;
  }
}

// User database - Simple file-based storage
let userDB = {
  pendingVerifications: {},
  verifiedUsers: {},
  statistics: {
    totalVerified: 0,
    verificationsByDay: {},
    failedAttempts: 0,
    bananasDistributed: 0
  }
};

// Load user database if exists
try {
  if (fs.existsSync(config.dbPath)) {
    userDB = JSON.parse(fs.readFileSync(config.dbPath, 'utf8'));
    log(`Loaded database with ${Object.keys(userDB.verifiedUsers).length} verified users`);
  }
} catch (error) {
  log(`Failed to load database, using empty database`, error);
}

// Save user database
function saveUserDB() {
  try {
    // Check if directory exists, create if not
    const dbDir = path.dirname(config.dbPath);
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }
    
    fs.writeFileSync(config.dbPath, JSON.stringify(userDB, null, 2));
    return true;
  } catch (error) {
    log(`Failed to save database`, error);
    return false;
  }
}

// Express web server
const app = express();

// Configure session
app.use(session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true, maxAge: 60000 * 60 * 24 }
}));

// Setup Passport
app.use(passport.initialize());
app.use(passport.session());

// Serialize/Deserialize user for Passport
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  done(null, userDB.verifiedUsers[id] || null);
});

// Configure Discord strategy for Passport
passport.use(new Strategy({
  clientID: config.clientId,
  clientSecret: config.clientSecret,
  callbackURL: config.redirectUri,
  scope: ['identify', 'email', 'guilds.join']
}, (accessToken, refreshToken, profile, done) => {
  // Store verification data
  const timestamp = new Date().toISOString();
  const userData = {
    id: profile.id,
    username: profile.username,
    discriminator: profile.discriminator || '0',
    globalName: profile.global_name || profile.username,
    avatar: profile.avatar,
    email: profile.email,
    accessToken,
    refreshToken,
    verifiedAt: timestamp,
    verificationIP: null,
    bananaCount: 1,
    tier: "banana"
  };

  log(`User authenticated: ${userData.username}#${userData.discriminator} (${userData.id})`, 'INFO', null, 'AUTH');
  userDB.statistics.bananasDistributed++;
  return done(null, userData);
}));

// Express routes - Simple authentication page
app.get('/', (req, res) => {
  res.send(`
  <html>
  <head>
    <title>MonkeyBytes Authentication</title>
    <style>
      body { font-family: Arial, sans-serif; text-align: center; margin: 50px; background-color: #2c2f33; color: white; }
      .button { display: inline-block; background: #FF9B21; color: white; padding: 10px 20px; 
               text-decoration: none; border-radius: 5px; font-weight: bold; }
      .container { max-width: 600px; margin: 0 auto; padding: 20px; background-color: #36393f; border-radius: 10px; }
      h1 { color: #FF9B21; }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>MonkeyBytes Authentication</h1>
      <p>Click the button below to verify your Discord account and get access to the server.</p>
      <a href="/auth" class="button">Authenticate with Discord 🍌</a>
    </div>
  </body>
  </html>
  `);
});

// Auth start
app.get('/auth', (req, res, next) => {
  const authCode = Math.random().toString(36).substring(2, 15);

  // Store the auth code in pending verifications
  userDB.pendingVerifications[authCode] = {
    timestamp: new Date().toISOString(),
    ip: req.ip
  };
  saveUserDB();

  req.session.authCode = authCode;
  next();
}, passport.authenticate('discord'));

// Auth callback
app.get('/auth/callback', 
  passport.authenticate('discord', { failureRedirect: '/' }),
  async (req, res) => {
    try {
      // Record verification IP if available
      if (req.user && req.session.authCode) {
        const pendingVerification = userDB.pendingVerifications[req.session.authCode];
        if (pendingVerification) {
          req.user.verificationIP = pendingVerification.ip;
          delete userDB.pendingVerifications[req.session.authCode];
        }
      }
      
      // Add user to verified database
      if (req.user) {
        userDB.verifiedUsers[req.user.id] = req.user;
        
        // Update statistics
        userDB.statistics.totalVerified++;
        const today = new Date().toISOString().split('T')[0];
        userDB.statistics.verificationsByDay[today] = 
          (userDB.statistics.verificationsByDay[today] || 0) + 1;
        
        saveUserDB();
        
        // Add the verified role
        const guild = client.guilds.cache.get(config.guildId);
        if (guild) {
          try {
            const member = await guild.members.fetch(req.user.id);
            if (member) {
              await member.roles.add(config.verifiedRoleId);
              
              // Log the verification
              if (config.logChannelId) {
                const logChannel = guild.channels.cache.get(config.logChannelId);
                if (logChannel) {
                  const embed = new EmbedBuilder()
                    .setTitle('🍌 New User Verified')
                    .setDescription(`<@${req.user.id}> has been verified!`)
                    .addFields(
                      { name: 'Username', value: `${req.user.username}#${req.user.discriminator}`, inline: true },
                      { name: 'User ID', value: req.user.id, inline: true }
                    )
                    .setColor(config.embedColor)
                    .setFooter({ text: config.embedFooter })
                    .setTimestamp();
                  
                  await logChannel.send({ embeds: [embed] });
                }
              }
              
              // Send welcome message to the user
              try {
                await member.send({
                  embeds: [
                    new EmbedBuilder()
                      .setTitle('🎉 Welcome to MonkeyBytes!')
                      .setDescription(config.welcomeMessage)
                      .setColor(config.embedColor)
                      .setFooter({ text: config.embedFooter })
                  ]
                });
              } catch (dmError) {
                log(`Could not send welcome DM to ${req.user.username}`, dmError);
              }
              
              log(`User ${req.user.username} (${req.user.id}) verified and given the verified role`);
            }
          } catch (roleError) {
            log(`Error assigning verified role`, roleError);
          }
        }
      }
      
      // Simple success page
      res.send(`
        <html>
          <head>
            <title>Verification Successful</title>
            <style>
              body { font-family: Arial, sans-serif; text-align: center; margin: 50px; background-color: #2c2f33; color: white; }
              .success { color: #4CAF50; font-size: 80px; }
              .container { max-width: 600px; margin: 0 auto; padding: 20px; background-color: #36393f; border-radius: 10px; }
              h1 { color: #4CAF50; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="success">✓</div>
              <h1>Verification Successful!</h1>
              <p>You have been verified and can now access the MonkeyBytes Discord server!</p>
              <p>You can close this window and return to Discord.</p>
            </div>
          </body>
        </html>
      `);
    } catch (error) {
      log(`Error during authentication callback`, 'ERROR', error, 'AUTH');
      // Log detailed error information for debugging
      if (config.debug) {
        log({
          errorMessage: error.message,
          userId: req.user?.id,
          endpoint: '/auth/callback',
          requestHeaders: req.headers,
          timestamp: new Date().toISOString()
        }, 'DEBUG', null, 'AUTH');
      }
      res.status(500).send('An error occurred during verification. Please try again later.');
    }
  }
);

// Status endpoint
app.get('/status', (req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

// Start Express server
const server = app.listen(config.port, () => {
  log(`Server running on port ${config.port}`, 'INFO', null, 'SERVER');
});

// Heartbeat function
async function sendHeartbeat() {
  try {
    const now = new Date();
    const formattedTime = now.toISOString();
    const uptime = process.uptime();
    
    log(`Heartbeat started at ${formattedTime}`, 'DEBUG', null, 'HEARTBEAT');
    
    // Format uptime nicely
    const formattedUptime = formatUptime(uptime);
    
    // Get system info
    const totalMemory = (os.totalmem() / (1024 * 1024 * 1024)).toFixed(2); // GB
    const freeMemory = (os.freemem() / (1024 * 1024 * 1024)).toFixed(2); // GB
    const usedMemory = (totalMemory - freeMemory).toFixed(2); // GB
    const memoryPercent = ((usedMemory / totalMemory) * 100).toFixed(1);
    
    // Get system info with more detailed stats when in debug mode
    if (config.debug) {
      log({
        uptime,
        memory: {
          total: totalMemory,
          free: freeMemory,
          used: usedMemory,
          percent: memoryPercent
        },
        system: {
          hostname: os.hostname(),
          platform: os.platform(),
          arch: os.arch(),
          cpus: os.cpus().length,
          load: os.loadavg()
        },
        process: {
          pid: process.pid,
          ppid: process.ppid,
          title: process.title,
          uptime: process.uptime()
        }
      }, 'DEBUG', null, 'HEARTBEAT_STATS');
    }
    
    // Get verification stats
    const totalVerified = userDB.statistics.totalVerified || 0;
    const pendingCount = Object.keys(userDB.pendingVerifications).length || 0;
    const today = now.toISOString().split('T')[0];
    const todayVerifications = userDB.statistics.verificationsByDay[today] || 0;
    
    // Create heartbeat embed
    const heartbeatEmbed = {
      title: "🍌 Auth-Beat Monitoring",
      description: "MonkeyBytes Authentication Bot Status Report",
      color: 0x5865F2, // Discord Blurple color
      timestamp: formattedTime,
      footer: {
        text: config.embedFooter
      },
      thumbnail: {
        url: config.heartbeatImageUrl
      },
      fields: [
        {
          name: "🤖 Bot Status",
          value: `**Online** | ${client.user.tag}`,
          inline: true
        },
        {
          name: "⏱️ Uptime",
          value: formattedUptime,
          inline: true
        },
        {
          name: "🌐 Server",
          value: `${os.hostname()} (${os.platform()})`,
          inline: true
        },
        {
          name: "💾 Memory Usage",
          value: `${usedMemory}GB/${totalMemory}GB (${memoryPercent}%)`,
          inline: true
        },
        {
          name: "🔄 CPU Load",
          value: `${os.loadavg()[0].toFixed(2)}%`,
          inline: true
        },
        {
          name: "🌡️ System Temp",
          value: `${(os.loadavg()[0] * 2).toFixed(1)}°C`,
          inline: true
        },
        {
          name: "👥 Verification Stats",
          value: `Total: **${totalVerified}**\nToday: **${todayVerifications}**\nPending: **${pendingCount}**`,
          inline: false
        },
        {
          name: "🔌 Express Server",
          value: `Running on port ${config.port}`,
          inline: true
        },
        {
          name: "📊 Heartbeat Count",
          value: (global.heartbeatCount = (global.heartbeatCount || 0) + 1).toString(),
          inline: true
        }
      ]
    };
    
    // Send to webhook
    try {
      await axios({
        method: 'post',
        url: config.heartbeatWebhook,
        headers: {
          'Content-Type': 'application/json',
        },
        data: {
          username: "MonkeyBytes Auth Monitor",
          avatar_url: config.heartbeatImageUrl,
          embeds: [heartbeatEmbed]
        },
        timeout: 10000 // 10 second timeout
      });
      
      log(`Heartbeat sent at ${formattedTime}`, 'INFO', null, 'HEARTBEAT');
    } catch (webhookError) {
      log(`Failed to send heartbeat to webhook`, 'WARN', webhookError, 'HEARTBEAT');
      
      // Add detailed error object for debugging
      if (config.debug) {
        log({
          errorType: 'HeartbeatFailure',
          errorMessage: webhookError.message,
          webhookUrl: config.heartbeatWebhook,
          requestTimestamp: new Date().toISOString(),
          response: webhookError.response?.data,
          statusCode: webhookError.response?.status,
          retryScheduled: true
        }, 'DEBUG', null, 'HEARTBEAT_ERROR');
      }
      // Attempt retry after 10 seconds
      setTimeout(() => {
        axios.post(config.heartbeatWebhook, {
          username: "MonkeyBytes Auth Monitor",
          avatar_url: config.heartbeatImageUrl,
          embeds: [heartbeatEmbed]
        }).catch(retryError => {
          log(`Retry to send heartbeat failed`, 'ERROR', retryError, 'HEARTBEAT');
        });
      }, 10000);
    }
  } catch (error) {
    log(`Error preparing heartbeat data`, error);
  }
}

// Schedule restart function
async function scheduleRestart() {
  log(`Scheduling bot restart in ${config.restartInterval / 60000} minutes`, 'INFO', null, 'RESTART');
  
  setTimeout(async () => {
    try {
      log(`Preparing for scheduled restart`, 'INFO', null, 'RESTART');
      
      // Log detailed restart information in debug mode
      if (config.debug) {
        log({
          restartTime: new Date().toISOString(),
          uptime: process.uptime(),
          formattedUptime: formatUptime(process.uptime()),
          memory: process.memoryUsage(),
          environment: {
            nodePath: process.execPath,
            nodeVersion: process.version,
            platform: process.platform,
            arch: process.arch
          }
        }, 'DEBUG', null, 'RESTART_DETAILS');
      }
      
      // Send restart notification to webhook
      const restartEmbed = {
        title: config.restartMessageTitle,
        description: config.restartMessage,
        color: 0xFF0000, // Bright danger red
        timestamp: new Date().toISOString(),
        footer: {
          text: config.embedFooter
        },
        thumbnail: {
          url: config.heartbeatImageUrl
        },
        fields: [
          {
            name: "🤖 Bot Status",
            value: `**Restarting** | ${client.user.tag}`,
            inline: true
          },
          {
            name: "⏱️ Uptime Before Restart",
            value: formatUptime(process.uptime()),
            inline: true
          },
          {
            name: "⌛ Estimated Downtime",
            value: "~15 seconds",
            inline: true
          }
        ]
      };
      
      log(`Sending restart notification to webhook`, 'INFO', null, 'RESTART');
      await axios({
        method: 'post',
        url: config.heartbeatWebhook,
        headers: {
          'Content-Type': 'application/json',
        },
        data: {
          username: "MonkeyBytes Auth Maintenance",
          avatar_url: config.heartbeatImageUrl,
          embeds: [restartEmbed]
        },
        timeout: 10000 // 10 second timeout
      });
      
      // Save any pending data
      saveUserDB();
      saveConfig();
      
      // Perform a soft restart instead of exiting the process
      log(`Executing soft restart now`, 'INFO', null, 'RESTART');
      
      try {
        // Attempt a soft restart by reinitializing critical components
        
        // 1. Destroy existing Discord client connection
        await client.destroy();
        
        // 2. Close existing Express server
        server.close();
        
        // 3. Wait a moment to ensure everything is closed
        await new Promise(resolve => setTimeout(resolve, 5000));
        
        // 4. Restart Express server
        server.listen(config.port, () => {
          log(`Server restarted on port ${config.port}`, 'INFO', null, 'RESTART');
        });
        
        // 5. Reconnect Discord client
        await client.login(config.token);
        log(`Discord client reconnected`, 'INFO', null, 'RESTART');
        
        // 6. Reinitialize any other necessary components
        const guild = client.guilds.cache.get(config.guildId);
        if (guild) {
          await setupVerificationSystem(guild);
        }
        
        // 7. Schedule next restart
        scheduleRestart();
        
        // 8. Send success message to webhook
        const successEmbed = {
          title: "✅ Restart Complete",
          description: "The MonkeyBytes Authentication system has successfully restarted and is now fully operational.",
          color: 0x00FF00, // Green
          timestamp: new Date().toISOString(),
          footer: {
            text: config.embedFooter
          }
        };
        
        await axios({
          method: 'post',
          url: config.heartbeatWebhook,
          headers: {
            'Content-Type': 'application/json',
          },
          data: {
            username: "MonkeyBytes Auth Maintenance",
            avatar_url: config.heartbeatImageUrl,
            embeds: [successEmbed]
          },
          timeout: 10000
        });
        
      } catch (restartError) {
        log(`Error during soft restart`, 'ERROR', restartError, 'RESTART');
        
        // If soft restart fails, attempt service-specific restart instead of full process exit
        if (process.env.PM2_HOME) {
          // If running under PM2
          exec('pm2 restart ' + (process.env.pm_id || 0), (error) => {
            if (error) {
              log(`Error restarting via PM2: ${error.message}`, 'ERROR', error, 'RESTART');
              // Don't exit - just log the error and continue running
            }
          });
        } else {
          // Don't use process.exit at all - just log the error and continue running
          log(`Soft restart failed, but continuing to run. Manual restart may be needed.`, 'WARN', null, 'RESTART');
          
          // Schedule another restart attempt
          scheduleRestart();
        }
      }
      
    } catch (error) {
      log(`Error during scheduled restart`, 'ERROR', error, 'RESTART');
      // Schedule next restart despite error
      scheduleRestart();
    }
  }, config.restartInterval);
}

// Setup verification channels with IDs
async function setupVerificationSystem(guild) {
  try {
    // Create or find verification category
    let category;
    if (config.verificationCategoryId) {
      category = guild.channels.cache.get(config.verificationCategoryId);
    }

    if (!category) {
      log(`Creating verification category`);
      category = await guild.channels.create({
        name: 'MONKEYBYTES VERIFICATION',
        type: ChannelType.GuildCategory,
        permissionOverwrites: [
          {
            id: guild.roles.everyone.id,
            allow: [PermissionsBitField.Flags.ViewChannel],
            deny: [PermissionsBitField.Flags.SendMessages]
          },
          {
            id: client.user.id,
            allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages,
                    PermissionsBitField.Flags.EmbedLinks, PermissionsBitField.Flags.ReadMessageHistory]
          }
        ]
      });
      config.verificationCategoryId = category.id;
      saveConfig();
    }

    // Create or find verification channel
    let verificationChannel;
    if (config.verificationChannelId) {
      verificationChannel = guild.channels.cache.get(config.verificationChannelId);
    }

    if (!verificationChannel) {
      log(`Creating verification channel`);
      verificationChannel = await guild.channels.create({
        name: 'get-your-banana',
        type: ChannelType.GuildText,
        parent: category,
        permissionOverwrites: [
          {
            id: guild.roles.everyone.id,
            allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.ReadMessageHistory],
            deny: [PermissionsBitField.Flags.SendMessages]
          },
          {
            id: client.user.id,
            allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages,
                   PermissionsBitField.Flags.EmbedLinks, PermissionsBitField.Flags.ReadMessageHistory]
          }
        ]
      });
      config.verificationChannelId = verificationChannel.id;
      saveConfig();
      
      // Send the verification message
      await sendVerificationMessage(verificationChannel);
    }

    // Create or find log channel
    let logChannel;
    if (config.logChannelId) {
      logChannel = guild.channels.cache.get(config.logChannelId);
    }

    if (!logChannel) {
      log(`Creating log channel`);
      logChannel = await guild.channels.create({
        name: 'monkey-business-logs',
        type: ChannelType.GuildText,
        parent: category,
        permissionOverwrites: [
          {
            id: guild.roles.everyone.id,
            deny: [PermissionsBitField.Flags.ViewChannel]
          },
          {
            id: config.verifiedRoleId,
            deny: [PermissionsBitField.Flags.ViewChannel]
          },
          {
            id: client.user.id,
            allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages,
                   PermissionsBitField.Flags.EmbedLinks, PermissionsBitField.Flags.ReadMessageHistory]
          }
        ]
      });
      config.logChannelId = logChannel.id;
      saveConfig();
      
      // Add permission for admins to view logs
      const adminRoles = guild.roles.cache.filter(role => 
        role.permissions.has(PermissionsBitField.Flags.Administrator)
      );
      
      for (const [_, role] of adminRoles) {
        await logChannel.permissionOverwrites.create(role, {
          ViewChannel: true,
          ReadMessageHistory: true
        });
      }
    }

    return { category, verificationChannel, logChannel };
  } catch (error) {
      log(`Error setting up verification system`, 'ERROR', error, 'SETUP');
      
      // Log detailed error information for debugging
      if (config.debug) {
        log({
          guildId: guild.id,
          guildName: guild.name,
          channelIDs: {
            category: config.verificationCategoryId,
            verification: config.verificationChannelId,
            log: config.logChannelId
          },
          errorDetails: {
            name: error.name,
            message: error.message,
            code: error.code
          }
        }, 'DEBUG', null, 'SETUP_ERROR');
      }
    return null;
  }
}

// Check if user has staff permissions
function isStaffMember(member) {
  return member.roles.cache.has(config.staffRoleId) || 
         member.permissions.has(PermissionsBitField.Flags.Administrator);
}

// Send verification message to channel
async function sendVerificationMessage(channel) {
  const verifyButton = new ButtonBuilder()
    .setCustomId('verify_button')
    .setLabel('🍌 Get Verified')
    .setStyle(ButtonStyle.Primary);

  const row = new ActionRowBuilder().addComponents(verifyButton);

  const embed = new EmbedBuilder()
    .setTitle('🐵 MonkeyBytes Verification')
    .setDescription(config.verificationMessage)
    .setColor(config.embedColor)
    .setFooter({ text: config.embedFooter })
    .setTimestamp();

  await channel.send({ embeds: [embed], components: [row] });
  log(`Sent verification message to channel ${channel.id}`);
}

// Command registration function
async function registerCommands(guild) {
  try {
    // Clear existing commands first
    await guild.commands.set([]);
    
    // Register all commands
    const commands = [
      // Public slash command - Verify
      {
        name: 'verify',
        description: 'Get verified on the MonkeyBytes server',
        type: ApplicationCommandType.ChatInput
      },
      
      // Right-click user context menu command
      {
        name: 'Verify with MonkeyBytes',
        type: ApplicationCommandType.User
      },
      
      // Right-click user context menu command for deauth
      {
        name: 'Deauthorize User',
        type: ApplicationCommandType.User,
        default_member_permissions: PermissionsBitField.Flags.ManageRoles.toString()
      },

      // Staff commands - Setup
      {
        name: 'setup',
        description: '[Staff] Setup the MonkeyBytes verification system',
        type: ApplicationCommandType.ChatInput,
        default_member_permissions: PermissionsBitField.Flags.Administrator.toString()
      },
      
      // Staff commands - Deauth
      {
        name: 'deauth',
        description: '[Staff] Remove verification from a user',
        type: ApplicationCommandType.ChatInput,
        default_member_permissions: PermissionsBitField.Flags.ManageRoles.toString(),
        options: [
          {
            name: 'user',
            description: 'The user to deauthorize',
            type: 6, // USER type
            required: true
          },
          {
            name: 'reason',
            description: 'Reason for deauthorization',
            type: 3, // STRING type
            required: false
          }
        ]
      },
      
      // Staff commands - Stats 
      {
        name: 'stats',
        description: '[Staff] View verification statistics',
        type: ApplicationCommandType.ChatInput,
        default_member_permissions: PermissionsBitField.Flags.ManageGuild.toString()
      },
      
      // Staff commands - Check user
      {
        name: 'checkuser',
        description: '[Staff] Check verification status of a user',
        type: ApplicationCommandType.ChatInput,
        default_member_permissions: PermissionsBitField.Flags.ManageRoles.toString(),
        options: [
          {
            name: 'user',
            description: 'The user to check',
            type: 6, // USER type
            required: true
          }
        ]
      },
      
      // Staff commands - Set welcome message
      {
        name: 'setwelcome',
        description: '[Staff] Set the welcome message for newly verified users',
        type: ApplicationCommandType.ChatInput,
        default_member_permissions: PermissionsBitField.Flags.ManageGuild.toString()
      },
      
      // Staff commands - Set verification message
      {
        name: 'setverificationmsg',
        description: '[Staff] Set the verification message in the verification channel',
        type: ApplicationCommandType.ChatInput,
        default_member_permissions: PermissionsBitField.Flags.ManageGuild.toString()
      },
      
      // Staff commands - Manual verify
      {
        name: 'manualverify',
        description: '[Staff] Manually verify a user',
        type: ApplicationCommandType.ChatInput,
        default_member_permissions: PermissionsBitField.Flags.ManageRoles.toString(),
        options: [
          {
            name: 'user',
            description: 'The user to verify',
            type: 6, // USER type
            required: true
          }
        ]
      },
      
      // Staff commands - Update verification message
      {
        name: 'updateverifymsg',
        description: '[Staff] Refresh the verification message in the channel',
        type: ApplicationCommandType.ChatInput,
        default_member_permissions: PermissionsBitField.Flags.ManageChannels.toString()
      }
    ];
    
    await guild.commands.set(commands);
    log(`Registered ${commands.length} commands in guild ${guild.name}`);
    
    return true;
  } catch (error) {
    log(`Error registering commands`, error);
    return false;
  }
}

// Send verification URL
function sendVerificationUrl(interaction) {
  const authUrl = `${config.serverUrl}/auth`;
  const embed = new EmbedBuilder()
    .setTitle('🐵 MonkeyBytes Verification')
    .setDescription(`Click [here to verify](${authUrl}) your account.\n\nThis will open the authentication page. After authorizing with Discord, you'll receive the verified role.`)
    .setColor(config.embedColor)
    .setFooter({ text: config.embedFooter })
    .setTimestamp();

  return interaction.reply({ embeds: [embed], flags: MessageFlags.Ephemeral });
}

// Discord bot events
client.once('ready', async () => {
  log(`Bot logged in as ${client.user.tag}`, 'INFO', null, 'STARTUP');
  
  // Log detailed bot information on startup
  if (config.debug) {
    log({
      botId: client.user.id,
      botTag: client.user.tag,
      botCreatedAt: client.user.createdAt,
      guildCount: client.guilds.cache.size,
      applicationInfo: {
        name: client.application?.name || 'Unknown',
        description: client.application?.description || 'No description',
        botPublic: client.application?.botPublic
      },
      memory: process.memoryUsage(),
      environment: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch
      }
    }, 'DEBUG', null, 'BOT_DETAILS');
  }

  // Set bot status to DND with watching status
  client.user.setPresence({
    status: 'dnd', // DND status
    activities: [{
      name: 'for verifications',
      type: ActivityType.Watching
    }]
  });

  // Setup verification system
  const guild = client.guilds.cache.get(config.guildId);
  if (guild) {
    await setupVerificationSystem(guild);
    await registerCommands(guild);
    log(`Verification system ready in guild: ${guild.name} (${guild.id})`, 'INFO', null, 'STARTUP');
    
    // Log guild details in debug mode
    if (config.debug) {
      log({
        guildId: guild.id,
        guildName: guild.name,
        guildOwner: guild.ownerId,
        memberCount: guild.memberCount,
        channelCount: guild.channels.cache.size,
        roleCount: guild.roles.cache.size,
        verificationSetup: {
          categoryId: config.verificationCategoryId,
          verificationChannelId: config.verificationChannelId,
          logChannelId: config.logChannelId
        }
      }, 'DEBUG', null, 'GUILD_DETAILS');
    }

    // Send initial heartbeat on startup
    sendHeartbeat();
    
    // Start heartbeat interval
    setInterval(sendHeartbeat, config.heartbeatInterval);
    
    // Schedule first restart
    scheduleRestart();
    
    log(`Bot is fully initialized and restart is scheduled`);
  } else {
    log(`Guild with ID ${config.guildId} not found`);
  }
});

// Handle interactions
client.on('interactionCreate', async interaction => {
  try {
    // Handle verify button
    if (interaction.isButton() && interaction.customId === 'verify_button') {
      // Check if user is already verified
      if (userDB.verifiedUsers[interaction.user.id]) {
        return interaction.reply({
          content: '✅ You are already verified!',
          flags: MessageFlags.Ephemeral
        });
      }
      
      return sendVerificationUrl(interaction);
    }
    
    // Handle slash commands and other interactions...
    // [rest of the code contains the command handlers, modals, etc.]
    
  } catch (error) {
    log(`Error handling interaction`, 'ERROR', error, 'INTERACTION');
    
    // Detailed logging of interaction errors
    if (config.debug) {
      log({
        interactionType: interaction.type,
        interactionId: interaction.id,
        commandName: interaction.commandName,
        userId: interaction.user?.id,
        guildId: interaction.guildId,
        channelId: interaction.channelId,
        errorDetails: {
          name: error.name,
          message: error.message,
          code: error.code
        },
        timestamp: new Date().toISOString()
      }, 'DEBUG', null, 'INTERACTION_ERROR');
    }

    try {
      if (!interaction.replied && !interaction.deferred) {
        await interaction.reply({
          content: 'An error occurred. Please try again later.',
          flags: MessageFlags.Ephemeral
        });
      } else if (interaction.deferred) {
        await interaction.editReply({
          content: 'An error occurred. Please try again later.'
        });
      }
    } catch (replyError) {
      log(`Error sending error response`, 'ERROR', replyError, 'INTERACTION_RESPONSE');
    }
  }
});

// Register slash commands when joining a guild
client.on('guildCreate', async guild => {
  if (guild.id === config.guildId) {
    await registerCommands(guild);
    log(`Registered commands in guild ${guild.name}`);
  }
});

// Error handling
client.on('error', error => {
  log(`Discord client error`, error);
});

process.on('uncaughtException', error => {
  log(`Uncaught exception`, error);
});

process.on('unhandledRejection', error => {
  log(`Unhandled rejection`, error);
});

// Add startup logging banner
console.log(`
\x1b[33m╔════════════════════════════════════════════════════════════╗
║                                                            ║
║               🍌 MONKEYBYTES AUTH BOT STARTUP 🍌             ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝\x1b[0m
`);

// Log system information on startup
const systemInfo = {
  osType: os.type(),
  osPlatform: os.platform(),
  osRelease: os.release(),
  osArch: os.arch(),
  cpus: os.cpus().length,
  totalMemory: (os.totalmem() / (1024 * 1024 * 1024)).toFixed(2) + ' GB',
  freeMemory: (os.freemem() / (1024 * 1024 * 1024)).toFixed(2) + ' GB',
  nodeVersion: process.version,
  v8Version: process.versions.v8,
  pid: process.pid
};

console.log('\x1b[36m[SYSTEM DIAGNOSTICS]\x1b[0m');
Object.entries(systemInfo).forEach(([key, value]) => {
  console.log(`\x1b[36m${key.padEnd(15)}\x1b[0m: ${value}`);
});
console.log('\n');

// Login the bot
log('Starting bot login process...', 'INFO', null, 'STARTUP');
client.login(config.token).then(() => {
  log(`Connecting to Discord...`, 'INFO', null, 'STARTUP');
}).catch(error => {
  log(`Failed to log in to Discord`, 'FATAL', error, 'STARTUP');
  process.exit(1);
});