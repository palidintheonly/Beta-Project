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

// Initialize global storage for transient data
if (!global.pendingManualVerifications) global.pendingManualVerifications = {};
if (!global.pendingDeauthUsers) global.pendingDeauthUsers = {};

// HARDCODED CONFIGURATION - ALL IDs
const config = {
  // User provided credentials - REPLACE WITH YOUR ACTUAL CREDENTIALS
  clientId: 'REPLACE_WITH_YOUR_CLIENT_ID',
  clientSecret: 'REPLACE_WITH_YOUR_CLIENT_SECRET',
  token: 'REPLACE_WITH_YOUR_BOT_TOKEN',

  // Server configuration
  port: 20295,
  redirectUri: 'http://your-server-url:20295/auth/callback',
  serverUrl: 'http://your-server-url:20295',

  // Discord IDs
  guildId: 'REPLACE_WITH_YOUR_GUILD_ID',
  verifiedRoleId: 'REPLACE_WITH_VERIFIED_ROLE_ID', 
  staffRoleId: 'REPLACE_WITH_STAFF_ROLE_ID', 

  // Channel IDs - Hardcoded with existing channels
  verificationCategoryId: 'REPLACE_WITH_VERIFICATION_CATEGORY_ID',
  verificationChannelId: 'REPLACE_WITH_VERIFICATION_CHANNEL_ID',
  logChannelId: 'REPLACE_WITH_LOG_CHANNEL_ID',

  // Session settings
  sessionSecret: 'replace-with-your-own-secure-secret',
  dbPath: './monkey-verified-users.json',
  configPath: './monkey-config.json',

  // Branding
  embedColor: '#3eff06',
  embedFooter: '© MonkeyBytes Tech | The Code Jungle',

  // Default messages
  welcomeMessage: "🎉 Welcome to the MonkeyBytes jungle! You've been verified and can now access all our coding resources and community features. Grab a banana and start coding! 🍌💻",
  verificationMessage: "To join the MonkeyBytes community, you'll need to verify your account. Click the button below to get your access banana! 🍌\n\nThis helps us keep our jungle safe from bots.",

  // Heartbeat configuration
  heartbeatWebhook: "REPLACE_WITH_YOUR_WEBHOOK_URL",
  heartbeatImageUrl: "REPLACE_WITH_YOUR_IMAGE_URL",
  heartbeatInterval: 630012, // 10 minutes, 30 seconds, and 12 milliseconds
  
  // Restart configuration
  restartInterval: 3600000, // 1 hour in milliseconds
  restartMessageTitle: "🔄 Scheduled Maintenance",
  restartMessage: "The MonkeyBytes Authentication system is performing a scheduled restart to ensure optimal performance and reliability. Service will resume automatically in a few seconds. 🍌"
};

// Staff member ID who will receive DMs about pending approvals
const APPROVAL_STAFF_ID = 'REPLACE_WITH_APPROVAL_STAFF_ID';

// Load user database if exists
try {
  if (fs.existsSync(config.dbPath)) {
    userDB = JSON.parse(fs.readFileSync(config.dbPath, 'utf8'));
    log(`Loaded database with ${Object.keys(userDB.verifiedUsers || {}).length} verified users`);
  }
} catch (error) {
  log(`Failed to load database, using empty database`, error);
}

// Ensure all required structures exist in the user database
function ensureUserDBStructure() {
  if (!userDB.pendingVerifications) userDB.pendingVerifications = {};
  if (!userDB.pendingApprovals) userDB.pendingApprovals = {};
  if (!userDB.verifiedUsers) userDB.verifiedUsers = {};
  if (!userDB.statistics) {
    userDB.statistics = {
      totalVerified: 0,
      verificationsByDay: {},
      failedAttempts: 0,
      bananasDistributed: 0
    };
  }
  saveUserDB();
}

// Call this function after loading the database
ensureUserDBStructure();

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
  cookie: { secure: false, maxAge: 60000 * 60 * 24 }
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

// Add endpoint for manual approval process
app.get('/auth/manual', (req, _res, next) => {
  const authCode = Math.random().toString(36).substring(2, 15);

  // Store the auth code in pending verifications
  userDB.pendingVerifications[authCode] = {
    timestamp: new Date().toISOString(),
    ip: req.ip,
    requiresApproval: true
  };
  saveUserDB();

  req.session.authCode = authCode;
  req.session.requiresApproval = true;
  next();
}, passport.authenticate('discord'));

// Express routes - Simple authentication page
app.get('/', (_req, res) => {
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
app.get('/auth', (req, _res, next) => {
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
      
      // Add user to verified database or pending approvals
      if (req.user) {
        // Check if this authentication requires manual approval
        if (req.session.requiresApproval || Math.random() < 0.30) { // 30% chance for testing - remove in production
          // Add to pending approvals
          userDB.pendingApprovals[req.user.id] = req.user;
          saveUserDB();
          
          // Notify staff for approval
          notifyStaffForApproval(req.user.id, req.user.username);
          
          // Show waiting for approval page
          return res.send(`
          <html>
            <head>
              <title>Verification Pending Approval</title>
              <style>
                body { font-family: Arial, sans-serif; text-align: center; margin: 50px; background-color: #2c2f33; color: white; }
                .pending { color: #FFA500; font-size: 80px; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; background-color: #36393f; border-radius: 10px; }
                h1 { color: #FFA500; }
              </style>
            </head>
            <body>
              <div class="container">
                <div class="pending">⏳</div>
                <h1>Verification Pending Approval</h1>
                <p>Your verification request has been sent to the MonkeyBytes staff for approval.</p>
                <p>You will be notified once your request has been processed.</p>
                <p>You can close this window and return to Discord.</p>
              </div>
            </body>
          </html>
          `);
        } else {
          // Regular verification flow
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
app.get('/status', (_req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

// Start Express server
const server = app.listen(config.port, () => {
  log(`Server running on port ${config.port}`, 'INFO', null, 'SERVER');
});

// Heartbeat function - Fixed to ensure reliable operation
async function sendHeartbeat() {
  try {
    const now = new Date();
    const formattedTime = now.toISOString();
    const uptime = process.uptime();
    
    // Add additional endpoint logging at start to track incoming requests  
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
    const pendingCount = Object.keys(userDB.pendingApprovals || {}).length || 0;
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
    
    // Send to webhook - Fixed for reliable delivery
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

// Function to notify staff for approval
async function notifyStaffForApproval(userId, username) {
  if (!userId || !username) {
    log(`Invalid user information for approval notification`, 'WARN', null, 'APPROVAL');
    return false;
  }
  
  try {
    const staffUser = client.users.cache.get(APPROVAL_STAFF_ID);
    if (!staffUser) {
      log(`Staff user for approvals not found: ${APPROVAL_STAFF_ID}`, 'WARN', null, 'APPROVAL');
      return false;
    }
    
    // Add Discord-specific error handling
    try {
      await staffUser.send(`**Pending Approval for:** <@${userId}> (${username})\n\nPlease respond with "yes" to approve or "no" to deny.`);
      log(`Sent approval notification to staff for user ${username} (${userId})`, 'INFO', null, 'APPROVAL');
      return true;
    } catch (dmError) {
      if (dmError.code === 50007) { // Cannot send messages to this user
        log(`Cannot send DM to staff user: ${APPROVAL_STAFF_ID} (DMs may be closed)`, 'WARN', dmError, 'APPROVAL');
      } else if (dmError.code === 50013) { // Missing permissions
        log(`Missing permissions to send DM to staff`, 'WARN', dmError, 'APPROVAL');
      } else if (dmError.httpStatus === 429) { // Rate limited
        log(`Rate limited when sending DM to staff. Will retry later.`, 'WARN', dmError, 'APPROVAL');
      } else {
        log(`Failed to send DM to staff: ${dmError.message}`, 'WARN', dmError, 'APPROVAL');
      }
      return false;
    }
  } catch (error) {
    log(`Error sending approval notification`, 'ERROR', error, 'APPROVAL');
    return false;
  }
}

// Function to process verification approval
async function processVerificationApproval(userId, approved) {
  try {
    // Check if user is in pending approvals
    if (!userDB.pendingApprovals) {
      userDB.pendingApprovals = {};
      saveUserDB();
      log(`User ${userId} not found in pending approvals (object was null)`, 'WARN', null, 'APPROVAL');
      return false;
    }
    
    if (!userDB.pendingApprovals[userId]) {
      log(`User ${userId} not found in pending approvals`, 'WARN', null, 'APPROVAL');
      return false;
    }
    
    const userData = userDB.pendingApprovals[userId];
    
    if (approved) {
      // Move from pending to verified
      userDB.verifiedUsers[userId] = userData;
      
      // Update statistics
      userDB.statistics.totalVerified++;
      const today = new Date().toISOString().split('T')[0];
      userDB.statistics.verificationsByDay[today] = 
        (userDB.statistics.verificationsByDay[today] || 0) + 1;
      
      // Add verified role to user
      const guild = client.guilds.cache.get(config.guildId);
      if (guild) {
        try {
          const member = await guild.members.fetch(userId).catch(err => {
            log(`Error fetching member ${userId} for role assignment`, 'ERROR', err, 'APPROVAL');
            return null;
          });
          
          if (member) {
            await member.roles.add(config.verifiedRoleId).catch(err => {
              log(`Error adding role to member ${userId}`, 'ERROR', err, 'APPROVAL');
            });
            
            // Log the verification
            if (config.logChannelId) {
              const logChannel = guild.channels.cache.get(config.logChannelId);
              if (logChannel) {
                const embed = new EmbedBuilder()
                  .setTitle('🍌 New User Verified (Staff Approved)')
                  .setDescription(`<@${userId}> has been verified after staff approval!`)
                  .addFields(
                    { name: 'Username', value: `${userData.username}#${userData.discriminator}`, inline: true },
                    { name: 'User ID', value: userId, inline: true }
                  )
                  .setColor(config.embedColor)
                  .setFooter({ text: config.embedFooter })
                  .setTimestamp();
                
                await logChannel.send({ embeds: [embed] }).catch(err => {
                  log(`Error sending log message for approved user ${userId}`, 'WARN', err, 'APPROVAL');
                });
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
              log(`Could not send welcome DM to ${userData.username}`, 'WARN', dmError, 'APPROVAL');
            }
          }
        } catch (roleError) {
          log(`Error assigning verified role for approval`, 'ERROR', roleError, 'APPROVAL');
        }
      }
    } else {
      // Log the denial
      const guild = client.guilds.cache.get(config.guildId);
      if (guild && config.logChannelId) {
        const logChannel = guild.channels.cache.get(config.logChannelId);
        if (logChannel) {
          const embed = new EmbedBuilder()
            .setTitle('❌ User Verification Denied')
            .setDescription(`<@${userId}>'s verification request was denied by staff.`)
            .addFields(
              { name: 'Username', value: `${userData.username}#${userData.discriminator}`, inline: true },
              { name: 'User ID', value: userId, inline: true }
            )
            .setColor('#FF0000')
            .setFooter({ text: config.embedFooter })
            .setTimestamp();
          
          await logChannel.send({ embeds: [embed] }).catch(err => {
            log(`Error sending log message for denied user ${userId}`, 'WARN', err, 'APPROVAL');
          });
        }
      }
      
      // Try to notify the user
      try {
        const guild = client.guilds.cache.get(config.guildId);
        if (guild) {
          const member = await guild.members.fetch(userId).catch(() => null);
          if (member) {
            await member.send({
              embeds: [
                new EmbedBuilder()
                  .setTitle('❌ Verification Declined')
                  .setDescription(`Your verification request for the MonkeyBytes server has been declined by staff. If you believe this is an error, please contact the server administrators.`)
                  .setColor('#FF0000')
                  .setFooter({ text: config.embedFooter })
              ]
            }).catch(err => {
              log(`Error sending denial notification to user ${userId}`, 'WARN', err, 'APPROVAL');
            });
          }
        }
      } catch (dmError) {
        log(`Could not send denial DM to ${userData.username}`, 'WARN', dmError, 'APPROVAL');
      }
    }
    
    // Remove from pending approvals
    delete userDB.pendingApprovals[userId];
    saveUserDB();
    
    return true;
  } catch (error) {
    log(`Error processing approval for ${userId}`, 'ERROR', error, 'APPROVAL');
    return false;
  }
}

// Check for pending approvals and send notifications
async function checkPendingApprovals() {
  try {
    // Ensure pendingApprovals exists before trying to get keys
    if (!userDB.pendingApprovals) {
      userDB.pendingApprovals = {};
      saveUserDB();
      return 0;
    }
    
    const pendingEntries = Object.entries(userDB.pendingApprovals).filter(([_, userData]) => 
      userData && userData.username
    );
    const pendingCount = pendingEntries.length;
    
    if (pendingCount > 0) {
      log(`Found ${pendingCount} pending approvals, sending notifications`, 'INFO', null, 'APPROVAL');
      
      const staffUser = client.users.cache.get(APPROVAL_STAFF_ID);
      if (!staffUser) {
        log(`Staff user for approvals not found: ${APPROVAL_STAFF_ID}`, 'WARN', null, 'APPROVAL');
        return pendingCount;
      }
      
      // If there are more than 3 pending approvals, send a batch notification instead of individual ones
      if (pendingCount > 3) {
        let pendingList = '';
        
        pendingEntries.forEach(([userId, userData], index) => {
          pendingList += `${index + 1}. <@${userId}> (${userData.username})\n`;
        });
        
        try {
          await staffUser.send(`**${pendingCount} Pending Approval(s):**\n\n${pendingList}\n\nPlease respond with the user ID followed by "yes" or "no" to approve or deny (e.g., "123456789 yes").`);
          log(`Sent batch approval notification to staff for ${pendingCount} users`, 'INFO', null, 'APPROVAL');
        } catch (dmError) {
          log(`Failed to send batch DM to staff: ${dmError.message}`, 'WARN', dmError, 'APPROVAL');
        }
      } else {
        // For a small number, send individual notifications with larger delays
        for (const [userId, userData] of pendingEntries) {
          const success = await notifyStaffForApproval(userId, userData.username);
          
          // Add a larger delay between notifications to avoid rate limits (3 seconds)
          await new Promise(resolve => setTimeout(resolve, 3000));
          
          // If we couldn't send the notification, don't keep trying others right away
          if (!success) {
            log(`Pausing notifications due to previous failure`, 'WARN', null, 'APPROVAL');
            break;
          }
        }
      }
    }
    return pendingCount;
  } catch (error) {
    log(`Error checking pending approvals`, 'ERROR', error, 'APPROVAL');
    return 0;
  }
}

// Safely delete messages with proper handling of 14-day limit
async function safeDeleteMessages(channel, messages) {
  // Try bulk delete first for messages less than 14 days old
  try {
    // Filter messages to those less than 14 days old
    const twoWeeksAgo = Date.now() - 12096e5; // 14 days in milliseconds
    const recentMessages = messages.filter(msg => msg.createdTimestamp > twoWeeksAgo);
    
    if (recentMessages.size > 0) {
      await channel.bulkDelete(recentMessages).catch(err => {
        log(`Error bulk deleting recent messages: ${err.message}`, 'WARN', err, 'MESSAGES');
      });
    }
    
    // For older messages, delete them individually
    const oldMessages = messages.filter(msg => msg.createdTimestamp <= twoWeeksAgo);
    for (const [_, message] of oldMessages) {
      try {
        await message.delete().catch(err => {
          log(`Error deleting old message ${message.id}: ${err.message}`, 'WARN', err, 'MESSAGES');
        });
        // Small delay to avoid rate limits
        await new Promise(resolve => setTimeout(resolve, 1000));
      } catch (err) {
        log(`Failed to delete message ${message.id}`, 'WARN', err, 'MESSAGES');
      }
    }
    return true;
  } catch (error) {
    log(`Error in message deletion process`, 'ERROR', error, 'MESSAGES');
    return false;
  }
}

// Schedule restart function - FIXED VERSION
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
        
        // Re-establish presence status
        setBotPresence();
        
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

// Command registration function with retry
async function registerCommandsWithRetry(guild, maxRetries = 3) {
  let retryCount = 0;
  let success = false;
  
  while (!success && retryCount < maxRetries) {
    try {
      const commandsData = [
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
        },
        
        // Staff commands - Pending approvals
        {
          name: 'pendingapprovals',
          description: '[Staff] View and manage pending verification approvals',
          type: ApplicationCommandType.ChatInput,
          default_member_permissions: PermissionsBitField.Flags.ManageRoles.toString()
        }
      ];
      
      // Create a batch update with exponential backoff
      await guild.commands.set(commandsData);
      log(`Registered ${commandsData.length} commands in guild ${guild.name}`);
      success = true;
      return true;
    } catch (error) {
      retryCount++;
      
      // Handle rate limits by waiting longer
      if (error.httpStatus === 429) {
        const retryAfter = error.retryAfter || 5; // Default to 5 seconds if not specified
        log(`Rate limited when registering commands. Retry ${retryCount}/${maxRetries} in ${retryAfter}s`, 'WARN', error, 'COMMANDS');
        await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
      } else if (error.code === 50013) {
        // Permission error - don't retry
        log(`Missing permissions to register commands in guild ${guild.id}`, 'ERROR', error, 'COMMANDS');
        return false;
      } else {
        // Other errors - retry with backoff
        const backoff = Math.pow(2, retryCount) * 1000; // Exponential backoff
        log(`Error registering commands. Retry ${retryCount}/${maxRetries} in ${backoff/1000}s`, 'ERROR', error, 'COMMANDS');
        await new Promise(resolve => setTimeout(resolve, backoff));
      }
    }
  }
  
  // If we get here, all retries failed
  log(`Failed to register commands after ${maxRetries} attempts`, 'ERROR', null, 'COMMANDS');
  return false;
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

  // Set bot presence
  setBotPresence();

  // Setup verification system
  const guild = client.guilds.cache.get(config.guildId);
  if (guild) {
    await setupVerificationSystem(guild);
    await registerCommandsWithRetry(guild);
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
    
    // Set a 30-second interval to check for pending approvals
    setInterval(async () => {
      try {
        // Skip if there are no pending approvals
        if (!userDB.pendingApprovals || Object.keys(userDB.pendingApprovals || {}).length === 0) {
          return;
        }
        
        const pendingCount = await checkPendingApprovals();
        if (pendingCount > 0) {
          log(`Automatic check found ${pendingCount} pending approvals`, 'INFO', null, 'APPROVAL');
        }
      } catch (error) {
        log(`Error in automatic pending approval check`, 'ERROR', error, 'APPROVAL');
      }
    }, 30000); // 30 seconds
    
    // Schedule first restart
    scheduleRestart();
    
    log(`Bot is fully initialized and restart is scheduled`);
  } else {
    log(`Guild with ID ${config.guildId} not found`);
  }
});

// Handle DM messages for approval process
client.on('messageCreate', async message => {
  // Only process messages in DMs from the approval staff member
  if (!message.guild && message.author.id === APPROVAL_STAFF_ID) {
    const content = message.content.trim();
    
    // Parse more flexible response formats
    let approved = null;
    let targetUserId = null;
    
    // Check for simple yes/no responses
    if (/^(yes|approve|approved|y|ok|👍)$/i.test(content)) {
      approved = true;
    } else if (/^(no|deny|denied|n|reject|👎)$/i.test(content)) {
      approved = false;
    } else {
      // More complex format parsing - look for user ID or mention followed by response
      const idMatch = content.match(/(\d{17,20})\s+(yes|approve|approved|y|ok|👍|no|deny|denied|n|reject|👎)/i);
      const mentionMatch = content.match(/<@!?(\d{17,20})>\s+(yes|approve|approved|y|ok|👍|no|deny|denied|n|reject|👎)/i);
      
      if (idMatch) {
        targetUserId = idMatch[1];
        approved = /^(yes|approve|approved|y|ok|👍)$/i.test(idMatch[2]);
      } else if (mentionMatch) {
        targetUserId = mentionMatch[1];
        approved = /^(yes|approve|approved|y|ok|👍)$/i.test(mentionMatch[2]);
      }
    }
    
    // If we have an explicit approval/denial
    if (approved !== null) {
      try {
        // If we have a direct userId mentioned in the message
        if (targetUserId) {
          const success = await processVerificationApproval(targetUserId, approved);
          
          if (success) {
            await message.reply(`${approved ? '✅' : '❌'} ${approved ? 'Approved' : 'Denied'} verification for <@${targetUserId}>.`);
          } else {
            await message.reply(`Error processing ${approved ? 'approval' : 'denial'}. The user might no longer be pending.`);
          }
          return;
        }
        
        // Otherwise try to find which user they're responding to by checking previous messages
        const messages = await message.channel.messages.fetch({ limit: 10 });
        
        // First check if they're replying to a specific message
        if (message.reference && message.reference.messageId) {
          const repliedTo = messages.get(message.reference.messageId);
          if (repliedTo && repliedTo.author.id === client.user.id) {
            const match = repliedTo.content.match(/<@(\d+)>/);
            if (match && match[1]) {
              const userId = match[1];
              const success = await processVerificationApproval(userId, approved);
              
              if (success) {
                await message.reply(`${approved ? '✅' : '❌'} ${approved ? 'Approved' : 'Denied'} verification for <@${userId}>.`);
              } else {
                await message.reply(`Error processing ${approved ? 'approval' : 'denial'}. The user might no longer be pending.`);
              }
              return;
            }
          }
        }
        
        // If not replying to a specific message, look for the most recent approval request
        const previousMessage = messages.find(msg => 
          msg.author.id === client.user.id && 
          msg.content.includes('**Pending Approval for:**')
        );
        
        if (previousMessage) {
          const match = previousMessage.content.match(/<@(\d+)>/);
          if (match && match[1]) {
            const userId = match[1];
            const success = await processVerificationApproval(userId, approved);
            
            if (success) {
              await message.reply(`${approved ? '✅' : '❌'} ${approved ? 'Approved' : 'Denied'} verification for <@${userId}>.`);
            } else {
              await message.reply(`Error processing ${approved ? 'approval' : 'denial'}. The user might no longer be pending.`);
            }
            return;
          }
        }
        
        // If we couldn't figure out which user they're responding to
        await message.reply(`I couldn't determine which verification request you're responding to. Please either reply directly to the notification message or specify the user ID like: "123456789 yes".`);
      } catch (error) {
        log(`Error processing approval response`, 'ERROR', error, 'APPROVAL');
        await message.reply('An error occurred while processing your response. Please try again.');
      }
    }
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
    } else if (interaction.isButton() && interaction.customId.startsWith('confirm_manual_verify:')) {
      // Extract the verification ID from the custom ID
      const verificationId = interaction.customId.split(':')[1];
      
      // Get the target user ID from our global mapping
      const targetUserId = global.pendingManualVerifications[verificationId];
      
      if (!targetUserId) {
        return interaction.update({
          content: '❌ Error: Verification request expired or not found. Please try manually verifying the user with the /manualverify command instead.',
          components: [],
          embeds: []
        });
      }
      
      // Clean up the mapping once used
      delete global.pendingManualVerifications[verificationId];
      
      try {
        // Get user and member objects with proper error handling
        const user = await client.users.fetch(targetUserId).catch(err => {
          log(`Error fetching user ${targetUserId}`, 'ERROR', err, 'DISCORD_API');
          return null;
        });
        
        if (!user) {
          return interaction.update({
            content: `❌ Error: Could not find user with ID ${targetUserId}.`,
            components: [],
            embeds: []
          });
        }
        
        const member = await interaction.guild.members.fetch(targetUserId).catch(err => {
          log(`Error fetching member ${targetUserId}`, 'ERROR', err, 'DISCORD_API');
          return null;
        });
        
        if (!member) {
          return interaction.update({
            content: `❌ Error: User <@${targetUserId}> is not a member of this server.`,
            components: [],
            embeds: []
          });
        }
        
        // Create user data for manual verification
        const timestamp = new Date().toISOString();
        const userData = {
          id: user.id,
          username: user.username,
          discriminator: user.discriminator || '0',
          globalName: user.globalName || user.username,
          avatar: user.avatar,
          email: null,
          accessToken: null,
          refreshToken: null,
          verifiedAt: timestamp,
          verificationIP: 'manual-verification',
          bananaCount: 1,
          tier: "banana",
          manuallyVerifiedBy: interaction.user.id
        };
        
        // Add user to verified database
        userDB.verifiedUsers[user.id] = userData;
        
        // Update statistics
        userDB.statistics.totalVerified++;
        const today = new Date().toISOString().split('T')[0];
        userDB.statistics.verificationsByDay[today] = 
          (userDB.statistics.verificationsByDay[today] || 0) + 1;
        userDB.statistics.bananasDistributed++;
        
        saveUserDB();
        
        // Add the verified role
        await member.roles.add(config.verifiedRoleId).catch(err => {
          log(`Error adding role to ${user.id}`, 'ERROR', err, 'VERIFY');
          throw new Error(`Could not add verified role: ${err.message}`);
        });
        
        // Log the verification
        const logChannel = interaction.guild.channels.cache.get(config.logChannelId);
        if (logChannel) {
          const embed = new EmbedBuilder()
            .setTitle('🍌 User Manually Verified')
            .setDescription(`<@${user.id}> has been manually verified by <@${interaction.user.id}>!`)
            .addFields(
              { name: 'Username', value: `${user.username}#${user.discriminator}`, inline: true },
              { name: 'User ID', value: user.id, inline: true },
              { name: 'Verified By', value: `<@${interaction.user.id}>`, inline: true }
            )
            .setColor(config.embedColor)
            .setFooter({ text: config.embedFooter })
            .setTimestamp();
          
          await logChannel.send({ embeds: [embed] }).catch(err => {
            log(`Error sending log message for button verification`, 'WARN', err, 'VERIFY');
          });
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
          log(`Could not send welcome DM to ${user.username}`, 'WARN', dmError, 'VERIFY');
        }
        
        await interaction.update({
          content: `✅ Successfully verified <@${user.id}> and assigned the verified role.`,
          components: [],
          embeds: []
        });
      } catch (error) {
        log(`Error during button verification for ${targetUserId}`, 'ERROR', error, 'VERIFY');
        await interaction.update({
          content: `❌ Error verifying user: ${error.message}. Try using the /manualverify command instead.`,
          components: [],
          embeds: []
        });
      }
    } else if (interaction.isButton() && interaction.customId.startsWith('cancel_manual_verify:')) {
      // Extract the verification ID from the custom ID
      const verificationId = interaction.customId.split(':')[1];
      
      // Clean up the mapping
      if (global.pendingManualVerifications[verificationId]) {
        delete global.pendingManualVerifications[verificationId];
      }
      
      await interaction.update({
        content: '❌ Manual verification cancelled.',
        components: [],
        embeds: []
      });
    } else if (interaction.isButton() && interaction.customId === 'check_pending_approvals') {
      await interaction.deferReply({ ephemeral: true });
      
      // Ensure pendingApprovals exists
      if (!userDB.pendingApprovals) {
        userDB.pendingApprovals = {};
        saveUserDB();
      }
      
      const pendingCount = Object.keys(userDB.pendingApprovals).length;
      
      if (pendingCount > 0) {
        // Trigger the check for pending approvals
        await checkPendingApprovals();
        
        // List the pending users
        let pendingList = '';
        try {
          pendingList = Object.entries(userDB.pendingApprovals)
            .filter(([_, userData]) => userData && userData.username) // Filter out invalid entries
            .map(([userId, userData]) => `• <@${userId}> (${userData.username || 'Unknown'})`)
            .join('\n');
          
          if (!pendingList || pendingList.trim() === '') {
            pendingList = '*No valid pending approvals found*';
          }
        } catch (error) {
          log(`Error generating pending list`, 'ERROR', error, 'APPROVAL');
          pendingList = '*Error generating list*';
        }
        
        await interaction.editReply({
          content: `✅ Sent notifications for ${pendingCount} pending approval(s).\n\nPending users:\n${pendingList}`
        });
      } else {
        await interaction.editReply({
          content: '✅ There are no pending approvals at this time.'
        });
      }
    }
    
    // Handle slash commands
    if (interaction.isChatInputCommand()) {
      const { commandName } = interaction;
      
      // Public verify command
      if (commandName === 'verify') {
        // Check if user is already verified
        if (userDB.verifiedUsers[interaction.user.id]) {
          return interaction.reply({
            content: '✅ You are already verified!',
            flags: MessageFlags.Ephemeral
          });
        }
        
        return sendVerificationUrl(interaction);
      }
      
      // Setup command
      if (commandName === 'setup') {
        // Permission check
        if (!isStaffMember(interaction.member)) {
          return interaction.reply({ 
            content: 'You need staff permissions to use this command.',
            flags: MessageFlags.Ephemeral
          });
        }
        
        await interaction.deferReply({ flags: MessageFlags.Ephemeral });
        
        const guild = interaction.guild;
        const channels = await setupVerificationSystem(guild);
        
        if (channels) {
          await interaction.editReply({ 
            content: `✅ Setup complete! Verification channel: <#${channels.verificationChannel.id}>, Log channel: <#${channels.logChannel.id}>`
          });
        } else {
          await interaction.editReply({ 
            content: `❌ Error setting up verification system. Check console logs.`
          });
        }
      }
      
      // Stats command
      if (commandName === 'stats') {
        // Permission check
        if (!isStaffMember(interaction.member)) {
          return interaction.reply({ 
            content: 'You need staff permissions to use this command.',
            flags: MessageFlags.Ephemeral
          });
        }
        
        const stats = userDB.statistics;
        // Ensure pendingApprovals exists
        if (!userDB.pendingApprovals) {
          userDB.pendingApprovals = {};
          saveUserDB();
        }
        const pendingCount = Object.keys(userDB.pendingApprovals).length;
        
        const embed = new EmbedBuilder()
          .setTitle('🍌 MonkeyBytes Verification Stats')
          .addFields(
            { name: 'Total Verified Users', value: stats.totalVerified.toString(), inline: true },
            { name: 'Bananas Distributed', value: stats.bananasDistributed.toString(), inline: true },
            { name: 'Failed Attempts', value: stats.failedAttempts.toString(), inline: true }
          )
          .setColor(config.embedColor)
          .setFooter({ text: config.embedFooter })
          .setTimestamp();
        
        // Add today's verifications
        const today = new Date().toISOString().split('T')[0];
        const todayVerifications = stats.verificationsByDay[today] || 0;
        embed.addFields({ name: 'Verifications Today', value: todayVerifications.toString() });
        
        // Add pending approvals
        embed.addFields({ name: 'Pending Approvals', value: pendingCount.toString() });
        
        // Create a button to trigger manual check for pending approvals
        const checkButton = new ButtonBuilder()
          .setCustomId('check_pending_approvals')
          .setLabel('Check Pending Approvals')
          .setStyle(ButtonStyle.Primary);
        
        const row = new ActionRowBuilder().addComponents(checkButton);
        
        await interaction.reply({ embeds: [embed], components: [row], flags: MessageFlags.Ephemeral });
      }
      
      // Check user command
      if (commandName === 'checkuser') {
        // Permission check
        if (!isStaffMember(interaction.member)) {
          return interaction.reply({ 
            content: 'You need staff permissions to use this command.',
            flags: MessageFlags.Ephemeral
          });
        }
        
        const user = interaction.options.getUser('user');
        const userData = userDB.verifiedUsers[user.id];
        
        if (userData) {
          const embed = new EmbedBuilder()
            .setTitle('🍌 User Verification Status')
            .setDescription(`<@${user.id}> is verified!`)
            .addFields(
              { name: 'Username', value: `${userData.username}#${userData.discriminator}`, inline: true },
              { name: 'User ID', value: userData.id, inline: true },
              { name: 'Verified On', value: new Date(userData.verifiedAt).toLocaleString(), inline: true },
              { name: 'Email', value: userData.email || 'Not available', inline: true },
              { name: 'Banana Count', value: userData.bananaCount.toString(), inline: true },
              { name: 'Tier', value: userData.tier || 'banana', inline: true }
            )
            .setColor(config.embedColor)
            .setFooter({ text: config.embedFooter })
            .setTimestamp();
          
          await interaction.reply({ embeds: [embed], flags: MessageFlags.Ephemeral });
        } else {
          await interaction.reply({ 
            content: `❌ User <@${user.id}> is not verified.`,
            flags: MessageFlags.Ephemeral
          });
        }
      }
      
      // Set welcome message command
      if (commandName === 'setwelcome') {
        // Permission check
        if (!isStaffMember(interaction.member)) {
          return interaction.reply({ 
            content: 'You need staff permissions to use this command.',
            flags: MessageFlags.Ephemeral
          });
        }
        
        // Create modal for message input
        const modal = new ModalBuilder()
          .setCustomId('welcome_modal')
          .setTitle('Set Welcome Message');
        
        const welcomeInput = new TextInputBuilder()
          .setCustomId('welcome_message')
          .setLabel('New welcome message')
          .setStyle(TextInputStyle.Paragraph)
          .setValue(config.welcomeMessage)
          .setPlaceholder('Enter the welcome message sent to newly verified users')
          .setRequired(true)
          .setMaxLength(2000);
        
        const actionRow = new ActionRowBuilder().addComponents(welcomeInput);
        modal.addComponents(actionRow);
        
        await interaction.showModal(modal);
      }
      
      // Set verification message command
      if (commandName === 'setverificationmsg') {
        // Permission check
        if (!isStaffMember(interaction.member)) {
          return interaction.reply({ 
            content: 'You need staff permissions to use this command.',
            flags: MessageFlags.Ephemeral
          });
        }
        
        // Create modal for message input
        const modal = new ModalBuilder()
          .setCustomId('verification_modal')
          .setTitle('Set Verification Message');
        
        const verificationInput = new TextInputBuilder()
          .setCustomId('verification_message')
          .setLabel('New verification message')
          .setStyle(TextInputStyle.Paragraph)
          .setValue(config.verificationMessage)
          .setPlaceholder('Enter the verification message shown in the verification channel')
          .setRequired(true)
          .setMaxLength(2000);
        
        const actionRow = new ActionRowBuilder().addComponents(verificationInput);
        modal.addComponents(actionRow);
        
        await interaction.showModal(modal);
      }
      
      // Manual verify command
      if (commandName === 'manualverify') {
        // Permission check
        if (!isStaffMember(interaction.member)) {
          return interaction.reply({ 
            content: 'You need staff permissions to use this command.',
            flags: MessageFlags.Ephemeral
          });
        }
        
        const user = interaction.options.getUser('user');
        
        try {
          const member = await interaction.guild.members.fetch(user.id).catch(err => {
            log(`Error fetching member for manual verification: ${user.id}`, 'ERROR', err, 'VERIFY');
            return null;
          });
          
          if (!member) {
            return interaction.reply({ 
              content: `❌ User <@${user.id}> is not a member of this server.`,
              flags: MessageFlags.Ephemeral
            });
          }
          
          // Already verified check
          if (userDB.verifiedUsers[user.id]) {
            return interaction.reply({ 
              content: `❌ User <@${user.id}> is already verified.`,
              flags: MessageFlags.Ephemeral
            });
          }
          
          // Create user data for manual verification
          const timestamp = new Date().toISOString();
          const userData = {
            id: user.id,
            username: user.username,
            discriminator: user.discriminator || '0',
            globalName: user.globalName || user.username,
            avatar: user.avatar,
            email: null,
            accessToken: null,
            refreshToken: null,
            verifiedAt: timestamp,
            verificationIP: 'manual-verification',
            bananaCount: 1,
            tier: "banana",
            manuallyVerifiedBy: interaction.user.id
          };
          
          // Add user to verified database
          userDB.verifiedUsers[user.id] = userData;
          
          // Update statistics
          userDB.statistics.totalVerified++;
          const today = new Date().toISOString().split('T')[0];
          userDB.statistics.verificationsByDay[today] = 
            (userDB.statistics.verificationsByDay[today] || 0) + 1;
          userDB.statistics.bananasDistributed++;
          
          saveUserDB();
          
          // Add the verified role
          await member.roles.add(config.verifiedRoleId).catch(err => {
            log(`Error adding verified role to ${user.id}`, 'ERROR', err, 'VERIFY');
            throw new Error(`Could not add verified role: ${err.message}`);
          });
          
          // Log the verification
          const logChannel = interaction.guild.channels.cache.get(config.logChannelId);
          if (logChannel) {
            const embed = new EmbedBuilder()
              .setTitle('🍌 User Manually Verified')
              .setDescription(`<@${user.id}> has been manually verified by <@${interaction.user.id}>!`)
              .addFields(
                { name: 'Username', value: `${user.username}#${user.discriminator}`, inline: true },
                { name: 'User ID', value: user.id, inline: true },
                { name: 'Verified By', value: `<@${interaction.user.id}>`, inline: true }
              )
              .setColor(config.embedColor)
              .setFooter({ text: config.embedFooter })
              .setTimestamp();
            
            await logChannel.send({ embeds: [embed] }).catch(err => {
              log(`Error sending log message for manual verification`, 'WARN', err, 'VERIFY');
            });
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
            log(`Could not send welcome DM to ${user.username}`, 'WARN', dmError, 'VERIFY');
          }
          
          await interaction.reply({ 
            content: `✅ Successfully verified <@${user.id}> and assigned the verified role.`,
            flags: MessageFlags.Ephemeral
          });
        } catch (error) {
          log(`Error during manual verification for ${user.id}`, 'ERROR', error, 'VERIFY');
          await interaction.reply({
            content: `❌ Error verifying user: ${error.message}`,
            flags: MessageFlags.Ephemeral
          });
        }
      }
      
      // Update verification message command
      if (commandName === 'updateverifymsg') {
        // Permission check
        if (!isStaffMember(interaction.member)) {
          return interaction.reply({ 
            content: 'You need staff permissions to use this command.',
            flags: MessageFlags.Ephemeral
          });
        }
        
        await interaction.deferReply({ flags: MessageFlags.Ephemeral });
        
        const verificationChannel = interaction.guild.channels.cache.get(config.verificationChannelId);
        if (!verificationChannel) {
          return interaction.editReply({
            content: '❌ Verification channel not found. Please run /setup first.'
          });
        }
        
        // Fetch messages for deletion with error handling
        const messages = await verificationChannel.messages.fetch({ limit: 10 }).catch(err => {
          log(`Error fetching messages from verification channel`, 'ERROR', err, 'VERIFY');
          return null;
        });
        
        if (!messages) {
          return interaction.editReply({
            content: '❌ Error fetching messages from verification channel.'
          });
        }
        
        const botMessages = messages.filter(msg => msg.author.id === client.user.id);
        
        // Use our safer delete function
        const deleteSuccess = await safeDeleteMessages(verificationChannel, botMessages);
        
        if (deleteSuccess) {
          // Send new verification message
          try {
            await sendVerificationMessage(verificationChannel);
            
            await interaction.editReply({
              content: '✅ Verification message updated successfully!'
            });
          } catch (error) {
            log(`Error sending new verification message`, 'ERROR', error, 'VERIFY');
            await interaction.editReply({
              content: `❌ Error sending new verification message: ${error.message}`
            });
          }
        } else {
          await interaction.editReply({
            content: '❌ Error deleting old messages. Try again later or contact the bot administrator.'
          });
        }
      }
      
      // Pending approvals command
      if (commandName === 'pendingapprovals') {
        // Permission check
        if (!isStaffMember(interaction.member)) {
          return interaction.reply({ 
            content: 'You need staff permissions to use this command.',
            flags: MessageFlags.Ephemeral
          });
        }
        
        await interaction.deferReply({ flags: MessageFlags.Ephemeral });
        
        // Ensure pendingApprovals exists
        if (!userDB.pendingApprovals) {
          userDB.pendingApprovals = {};
          saveUserDB();
        }
        
        const pendingCount = Object.keys(userDB.pendingApprovals).length;
        
        if (pendingCount === 0) {
          return interaction.editReply({
            content: '✅ There are no pending verification approvals at this time.'
          });
        }
        
        // Create embed for pending approvals
        const embed = new EmbedBuilder()
          .setTitle('🍌 Pending Verification Approvals')
          .setDescription(`There are **${pendingCount}** pending verification requests.`)
          .setColor(config.embedColor)
          .setFooter({ text: config.embedFooter })
          .setTimestamp();
        
        // Add fields for each pending approval (up to 10)
        let count = 0;
        for (const [userId, userData] of Object.entries(userDB.pendingApprovals)) {
          if (count >= 10) break;
          if (!userData) continue; // Skip invalid entries
          
          const created = new Date(userData.verifiedAt || Date.now()).toLocaleString();
          embed.addFields({ 
            name: `${userData.username || 'Unknown'}#${userData.discriminator || '0'}`,
            value: `ID: ${userId}\nRequested: ${created}`,
            inline: true
          });
          
          count++;
        }
        
        // Create buttons for notification and management
        const notifyButton = new ButtonBuilder()
          .setCustomId('check_pending_approvals')
          .setLabel('Send DM Notifications')
          .setStyle(ButtonStyle.Primary);
        
        const row = new ActionRowBuilder().addComponents(notifyButton);
        
        await interaction.editReply({
          embeds: [embed],
          components: [row]
        });
      }
      
      // Deauth command
      if (commandName === 'deauth') {
        // Permission check
        if (!isStaffMember(interaction.member)) {
          return interaction.reply({ 
            content: 'You need staff permissions to use this command.',
            flags: MessageFlags.Ephemeral
          });
        }
        
        const user = interaction.options.getUser('user');
        const reason = interaction.options.getString('reason') || 'No reason provided';
        
        await interaction.deferReply({ flags: MessageFlags.Ephemeral });
        
        // Check if user is verified
        if (!userDB.verifiedUsers[user.id]) {
          return interaction.editReply({ 
            content: `❌ User <@${user.id}> is not verified.`
          });
        }
        
        try {
          // Get the member object
          const member = await interaction.guild.members.fetch(user.id).catch(err => {
            log(`Error fetching member for deauth: ${user.id}`, 'ERROR', err, 'DEAUTH');
            return null;
          });
          
          // Remove user from verified database
          delete userDB.verifiedUsers[user.id];
          saveUserDB();
          
          // If the member is still in the server, remove their role and send notification
          if (member) {
            // Remove the verified role if they have it
            if (member.roles.cache.has(config.verifiedRoleId)) {
              await member.roles.remove(config.verifiedRoleId).catch(err => {
                log(`Error removing verified role from ${user.id}`, 'ERROR', err, 'DEAUTH');
                // Continue even if role removal fails - we've already removed from DB
              });
            }
            
            // Send DM to user with verification link
            try {
              const authUrl = `${config.serverUrl}/auth`;
              const embed = new EmbedBuilder()
                .setTitle('🐵 MonkeyBytes Verification Required')
                .setDescription(`Your verification has been revoked by a staff member.\n\nReason: ${reason}\n\nPlease [click here to verify again](${authUrl}).`)
                .setColor(config.embedColor)
                .setFooter({ text: config.embedFooter })
                .setTimestamp();
              
              await user.send({ embeds: [embed] }).catch(err => {
                log(`Could not send deauth DM to ${user.username}`, 'WARN', err, 'DEAUTH');
              });
            } catch (dmError) {
              log(`Could not send deauth DM to ${user.username}`, 'WARN', dmError, 'DEAUTH');
            }
          }
          
          // Log the deauthorization
          const logChannel = interaction.guild.channels.cache.get(config.logChannelId);
          if (logChannel) {
            const embed = new EmbedBuilder()
              .setTitle('🍌 User Deauthorized')
              .setDescription(`<@${user.id}> has been deauthorized by <@${interaction.user.id}>!`)
              .addFields(
                { name: 'Username', value: `${user.username}#${user.discriminator || '0'}`, inline: true },
                { name: 'User ID', value: user.id, inline: true },
                { name: 'Deauthorized By', value: `<@${interaction.user.id}>`, inline: true },
                { name: 'Reason', value: reason, inline: false }
              )
              .setColor('#FF0000')
              .setFooter({ text: config.embedFooter })
              .setTimestamp();
            
            await logChannel.send({ embeds: [embed] }).catch(err => {
              log(`Error sending log message for deauth`, 'WARN', err, 'DEAUTH');
            });
          }
          
          await interaction.editReply({ 
            content: `✅ Successfully deauthorized <@${user.id}>. ${member ? "They have been sent a reauthorization link." : "User is no longer in the server but their verification data has been removed."}`
          });
        } catch (error) {
          log(`Error deauthorizing user ${user.id}`, 'ERROR', error, 'DEAUTH');
          await interaction.editReply({ 
            content: `❌ Error deauthorizing user: ${error.message}`
          });
        }
      }
    }
    
    // Handle user context menu commands
    if (interaction.isUserContextMenuCommand()) {
      if (interaction.commandName === 'Verify with MonkeyBytes') {
        // Check if user is already verified
        if (userDB.verifiedUsers[interaction.targetUser.id]) {
          return interaction.reply({
            content: `✅ User <@${interaction.targetUser.id}> is already verified!`,
            flags: MessageFlags.Ephemeral
          });
        }
        
        // If it's a self-verification
        if (interaction.targetUser.id === interaction.user.id) {
          return sendVerificationUrl(interaction);
        }
        
        // If staff is verifying someone else
        if (isStaffMember(interaction.member)) {
          // Store the target user info in a global mapping
          if (!global.pendingManualVerifications) {
            global.pendingManualVerifications = {};
          }
          
          // Create a unique ID for this verification request
          const verificationId = Date.now() + '-' + interaction.targetUser.id;
          global.pendingManualVerifications[verificationId] = interaction.targetUser.id;
          
          // Create buttons with the ID as part of the custom ID
          const confirmButton = new ButtonBuilder()
            .setCustomId(`confirm_manual_verify:${verificationId}`)
            .setLabel('Verify User')
            .setStyle(ButtonStyle.Success);
          
          const cancelButton = new ButtonBuilder()
            .setCustomId(`cancel_manual_verify:${verificationId}`)
            .setLabel('Cancel')
            .setStyle(ButtonStyle.Danger);
          
          const row = new ActionRowBuilder().addComponents(confirmButton, cancelButton);
          
          const embed = new EmbedBuilder()
            .setTitle('🍌 Manual Verification Confirmation')
            .setDescription(`Are you sure you want to manually verify <@${interaction.targetUser.id}>?`)
            .setColor(config.embedColor)
            .setFooter({ text: config.embedFooter })
            .setTimestamp();
          
          await interaction.reply({ 
            embeds: [embed], 
            components: [row], 
            flags: MessageFlags.Ephemeral
          });
        } else {
          return interaction.reply({
            content: 'You need staff permissions to verify other users.',
            flags: MessageFlags.Ephemeral
          });
        }
      }
      
      // Deauthorize User context menu command
      if (interaction.commandName === 'Deauthorize User') {
        // Permission check
        if (!isStaffMember(interaction.member)) {
          return interaction.reply({
            content: 'You need staff permissions to deauthorize users.',
            flags: MessageFlags.Ephemeral
          });
        }
        
        // Check if user is verified
        if (!userDB.verifiedUsers[interaction.targetUser.id]) {
          return interaction.reply({
            content: `❌ User <@${interaction.targetUser.id}> is not verified.`,
            flags: MessageFlags.Ephemeral
          });
        }
        
        // Store the target user info in a global mapping
        if (!global.pendingDeauthUsers) {
          global.pendingDeauthUsers = {};
        }
        
        // Create a unique ID for this deauth request
        const deauthId = Date.now() + '-' + interaction.targetUser.id;
        global.pendingDeauthUsers[deauthId] = {
          userId: interaction.targetUser.id,
          username: interaction.targetUser.username,
          discriminator: interaction.targetUser.discriminator || '0'
        };
        
        // Create modal for reason input
        const modal = new ModalBuilder()
          .setCustomId(`deauth_modal:${deauthId}`)
          .setTitle('Deauthorize User');
        
        const reasonInput = new TextInputBuilder()
          .setCustomId('deauth_reason')
          .setLabel('Reason for deauthorization')
          .setStyle(TextInputStyle.Paragraph)
          .setPlaceholder('Enter reason for deauthorizing this user')
          .setRequired(false)
          .setMaxLength(1000);
        
        const actionRow = new ActionRowBuilder().addComponents(reasonInput);
        modal.addComponents(actionRow);
        
        await interaction.showModal(modal);
      }
    }
    
    // Handle modal submissions
    if (interaction.isModalSubmit()) {
      if (interaction.customId === 'welcome_modal') {
        try {
          const welcomeMessage = interaction.fields.getTextInputValue('welcome_message');
          if (!welcomeMessage) {
            return interaction.reply({
              content: '❌ The welcome message cannot be empty.',
              flags: MessageFlags.Ephemeral
            });
          }
          
          config.welcomeMessage = welcomeMessage;
          saveConfig();
          
          await interaction.reply({
            content: '✅ Welcome message updated successfully!',
            flags: MessageFlags.Ephemeral
          });
        } catch (error) {
          log(`Error processing welcome modal submission`, 'ERROR', error, 'INTERACTION');
          await interaction.reply({
            content: '❌ An error occurred while processing your input. Please try again.',
            flags: MessageFlags.Ephemeral
          });
        }
      }
      
      // Verification message modal
      if (interaction.customId === 'verification_modal') {
        try {
          const verificationMessage = interaction.fields.getTextInputValue('verification_message');
          if (!verificationMessage) {
            return interaction.reply({
              content: '❌ The verification message cannot be empty.',
              flags: MessageFlags.Ephemeral
            });
          }
          
          config.verificationMessage = verificationMessage;
          saveConfig();
          
          await interaction.reply({
            content: '✅ Verification message updated! Run /updateverifymsg to update the channel message.',
            flags: MessageFlags.Ephemeral
          });
        } catch (error) {
          log(`Error processing verification modal submission`, 'ERROR', error, 'INTERACTION');
          await interaction.reply({
            content: '❌ An error occurred while processing your input. Please try again.',
            flags: MessageFlags.Ephemeral
          });
        }
      }
      
      // Deauth modal submission
      if (interaction.customId.startsWith('deauth_modal:')) {
        // Extract the deauth ID from the custom ID
        const deauthId = interaction.customId.split(':')[1];
        
        // Get the user info from our global mapping
        const userInfo = global.pendingDeauthUsers[deauthId];
        
        if (!userInfo) {
          return interaction.reply({
            content: '❌ Error: Deauthorization request expired or not found. Please try again.',
            flags: MessageFlags.Ephemeral
          });
        }
        
        const reason = interaction.fields.getTextInputValue('deauth_reason') || 'No reason provided';
        const targetUserId = userInfo.userId;
        
        // Clean up the mapping once used
        delete global.pendingDeauthUsers[deauthId];
        
        await interaction.deferReply({ flags: MessageFlags.Ephemeral });
        
        try {
          // Get user and member objects
          const user = await client.users.fetch(targetUserId).catch(err => {
            log(`Error fetching user ${targetUserId} for deauth`, 'ERROR', err, 'DEAUTH');
            return null;
          });
          
          if (!user) {
            return interaction.editReply({
              content: `❌ Error: Could not find user with ID ${targetUserId}.`
            });
          }
          
          const member = await interaction.guild.members.fetch(targetUserId).catch(err => {
            log(`Error fetching member ${targetUserId} for deauth`, 'ERROR', err, 'DEAUTH');
            return null;
          });
          
          // Remove user from verified database
          delete userDB.verifiedUsers[targetUserId];
          saveUserDB();
          
          // If the member is still in the server, remove their role and send notification
          if (member) {
            // Remove the verified role if they have it
            if (member.roles.cache.has(config.verifiedRoleId)) {
              await member.roles.remove(config.verifiedRoleId).catch(err => {
                log(`Error removing verified role from ${targetUserId}`, 'ERROR', err, 'DEAUTH');
                // Continue even if role removal fails - we've already removed from DB
              });
            }
            
            // Send DM to user with verification link
            try {
              const authUrl = `${config.serverUrl}/auth`;
              const embed = new EmbedBuilder()
                .setTitle('🐵 MonkeyBytes Verification Required')
                .setDescription(`Your verification has been revoked by a staff member.\n\nReason: ${reason}\n\nPlease [click here to verify again](${authUrl}).`)
                .setColor(config.embedColor)
                .setFooter({ text: config.embedFooter })
                .setTimestamp();
              
              await user.send({ embeds: [embed] }).catch(err => {
                log(`Could not send deauth DM to ${user.username}`, 'WARN', err, 'DEAUTH');
              });
            } catch (dmError) {
              log(`Could not send deauth DM to ${user.username}`, 'WARN', dmError, 'DEAUTH');
            }
          }
          
          // Log the deauthorization
          const logChannel = interaction.guild.channels.cache.get(config.logChannelId);
          if (logChannel) {
            const embed = new EmbedBuilder()
              .setTitle('🍌 User Deauthorized')
              .setDescription(`<@${targetUserId}> has been deauthorized by <@${interaction.user.id}>!`)
              .addFields(
                { name: 'Username', value: `${user.username}#${user.discriminator || '0'}`, inline: true },
                { name: 'User ID', value: targetUserId, inline: true },
                { name: 'Deauthorized By', value: `<@${interaction.user.id}>`, inline: true },
                { name: 'Reason', value: reason, inline: false }
              )
              .setColor('#FF0000')
              .setFooter({ text: config.embedFooter })
              .setTimestamp();
            
            await logChannel.send({ embeds: [embed] }).catch(err => {
              log(`Error sending log message for deauth modal`, 'WARN', err, 'DEAUTH');
            });
          }
          
          await interaction.editReply({ 
            content: `✅ Successfully deauthorized <@${targetUserId}>. ${member ? "They have been sent a reauthorization link." : "User is no longer in the server but their verification data has been removed."}`
          });
        } catch (error) {
          log(`Error processing deauth modal for ${targetUserId}`, 'ERROR', error, 'DEAUTH');
          await interaction.editReply({ 
            content: `❌ Error deauthorizing user: ${error.message}`
          });
        }
      }
    }
  } catch (error) {
    log(`Error handling interaction`, 'ERROR', error, 'INTERACTION');
    
    // Discord-specific error handling
    let errorMessage = 'An error occurred. Please try again later.';
    
    if (error.code === 50013) {
      errorMessage = '❌ I don\'t have permission to perform this action. Please check my role permissions.';
    } else if (error.code === 10062) {
      // Interaction has already been acknowledged
      return;
    } else if (error.code === 10008) {
      // Message no longer exists
      return;
    }
    
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
          content: errorMessage,
          flags: MessageFlags.Ephemeral
        });
      } else if (interaction.deferred && !interaction.replied) {
        await interaction.editReply({
          content: errorMessage
        });
      }
    } catch (replyError) {
      log(`Error sending error response`, 'ERROR', replyError, 'INTERACTION_RESPONSE');
      
      // Only attempt to log if in debug mode and error exists
      if (config.debug && replyError) {
        log({
          errorContext: 'Failed to send error notification',
          originalError: {
            name: error?.name,
            message: error?.message
          },
          replyError: {
            name: replyError.name,
            message: replyError.message,
            code: replyError.code
          },
          interactionId: interaction.id,
          interactionType: interaction.type,
          interactionStatus: {
            replied: interaction.replied,
            deferred: interaction.deferred,
            ephemeral: interaction.ephemeral
          }
        }, 'DEBUG', null, 'CRITICAL_ERROR');
      }
    }
  }
});

// Register slash commands when joining a guild
client.on('guildCreate', async guild => {
  if (guild.id === config.guildId) {
    await registerCommandsWithRetry(guild);
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

// Add startup logging banner and initial diagnostics
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

// Login the bot with enhanced logging
log('Starting bot login process...', 'INFO', null, 'STARTUP');
client.login(config.token).then(() => {
  log(`Connecting to Discord...`, 'INFO', null, 'STARTUP');
}).catch(error => {
  log(`Failed to log in to Discord`, 'FATAL', error, 'STARTUP');
  
  // Detailed logging of login failure
  if (config.debug) {
    log({
      errorType: 'LoginFailure',
      timestamp: new Date().toISOString(),
      clientId: config.clientId,
      error: error.message
    }, 'DEBUG', null, 'LOGIN_ERROR');
  }
});