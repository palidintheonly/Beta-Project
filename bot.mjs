// monkeybytes-auth-bot.mjs
// Simple Discord Authentication Bot for MonkeyBytes

import { Client, GatewayIntentBits, EmbedBuilder, ButtonBuilder, ActionRowBuilder, 
  ButtonStyle, PermissionsBitField, ChannelType, ActivityType, ApplicationCommandType,
  ModalBuilder, TextInputBuilder, TextInputStyle, MessageFlags } from 'discord.js';
import express from 'express';
import session from 'express-session';
import passport from 'passport';
import { Strategy } from 'passport-discord';
import fs from 'fs';
import path from 'path';
import axios from 'axios';
import os from 'os';

// ==================== CONFIGURATION ====================
const config = {
  // User provided credentials - SANITIZED
  clientId: 'DISCORD_CLIENT_ID',
  clientSecret: 'DISCORD_CLIENT_SECRET',
  token: 'DISCORD_BOT_TOKEN',

  // Server configuration
  port: 20295,
  redirectUri: 'http://example.com:20295/auth/callback',
  serverUrl: 'http://example.com:20295',

  // Discord IDs - SANITIZED
  guildId: 'GUILD_ID',
  verifiedRoleId: 'VERIFIED_ROLE_ID', 
  staffRoleId: 'STAFF_ROLE_ID', 
  verificationCategoryId: 'VERIFICATION_CATEGORY_ID',
  verificationChannelId: 'VERIFICATION_CHANNEL_ID',
  logChannelId: 'LOG_CHANNEL_ID',
  additionalVerificationChannelId: 'ADDITIONAL_VERIFICATION_CHANNEL_ID', // Additional specified channel for verification
  approvalChannelId: 'APPROVAL_CHANNEL_ID', // Channel for verification approval messages

  // Session settings
  sessionSecret: 'SESSION_SECRET',
  dbPath: './monkey-verified-users.json',

  // Branding
  embedColor: '#3eff06',
  embedFooter: '© MonkeyBytes Tech | The Code Jungle',
  welcomeMessage: "🎉 Authentication successful! Welcome to the MonkeyBytes jungle! 🌴\n\nYour verification has been approved by our staff team, and you now have full access to all our coding resources, channels, and community features.\n\n🐒 Don't be shy - introduce yourself in our community channels\n💻 Check out our code repositories and learning resources\n🍌 Enjoy your verified status and all the perks that come with it!\n\nIf you need any help, our moderator team is just a message away!",
  verificationMessage: "To join the MonkeyBytes community, you'll need to verify your account. Click the button below to begin the verification process! 🍌\n\nAfter you authenticate, a staff member will review and approve your request.\n\nThis verification system helps us keep our coding jungle safe and secure.",

  // Heartbeat configuration
  heartbeatWebhook: "DISCORD_WEBHOOK_URL",
  heartbeatInterval: 630000, // 10.5 minutes
};

// ==================== INITIALIZE CLIENT ====================
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.DirectMessages
  ]
});

// ==================== GLOBAL DATA ====================
// Initialize userDB with default structure to ensure it exists before any function calls
let userDB = {
  pendingVerifications: {},
  pendingApprovals: {},
  verifiedUsers: {},
  deauthorizedUsers: {}, // Track deauthorized users
  statistics: {
    totalVerified: 0,
    verificationsByDay: {},
    failedAttempts: 0,
    totalDeauths: 0
  }
};

// Global state for pending operations
const pendingManualVerifications = {};
const pendingDeauthUsers = {};

// ==================== LOGGING ====================
// ANSI color codes for colored console output
const colors = {
  RESET: '\x1b[0m',
  INFO: '\x1b[36m',     // Cyan
  SUCCESS: '\x1b[32m',  // Green
  WARN: '\x1b[33m',     // Yellow
  ERROR: '\x1b[31m',    // Red
  FATAL: '\x1b[41m\x1b[37m', // White on Red background
  DEBUG: '\x1b[90m',    // Gray
  COMPLETE: '\x1b[32m\x1b[1m', // Bright Green
  DANGER: '\x1b[31m\x1b[1m',   // Bright Red
  STARTUP: '\x1b[35m',  // Magenta
  JOB: '\x1b[94m',      // Light Blue
};

// Enhanced logging function with colored output
function log(message, level = 'INFO', error = null) {
  const timestamp = new Date().toISOString();
  const color = colors[level] || colors.INFO;
  const logPrefix = `${color}[${timestamp}] [${level}]${colors.RESET}`;
  
  // Output to console with color
  if (typeof message === 'object') {
    console.log(`${logPrefix} Object logging:`);
    console.log(message);
  } else {
    console.log(`${logPrefix} ${message}`);
  }
  
  // Log error if available with error color
  if (error) {
    console.error(`${colors.ERROR}[${timestamp}] [${level}] Error details:${colors.RESET}`, error);
    
    // Additional structured error information
    if (error.stack) {
      const stackLines = error.stack.split('\n');
      console.error(`${colors.DANGER}[${timestamp}] [STACK] ${stackLines[0]}${colors.RESET}`);
      for (let i = 1; i < Math.min(stackLines.length, 4); i++) {
        console.error(`${colors.DANGER}  ${stackLines[i]}${colors.RESET}`);
      }
    }
  }
}

// ==================== DATABASE FUNCTIONS ====================
// Function to ensure database directory exists
function ensureDatabaseDirectory() {
  try {
    const dbDir = path.dirname(config.dbPath);
    if (dbDir !== '.' && !fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
      log(`Created database directory: ${dbDir}`, 'SUCCESS');
    }
    return true;
  } catch (error) {
    log(`Failed to create database directory`, 'ERROR', error);
    return false;
  }
}

// Ensure the userDB has the correct structure
function ensureUserDBStructure() {
  // Make sure userDB is defined first
  if (!userDB) {
    userDB = {};
    log(`Created new userDB object`, 'STARTUP');
  }
  
  if (!userDB.pendingVerifications) userDB.pendingVerifications = {};
  if (!userDB.pendingApprovals) userDB.pendingApprovals = {};
  if (!userDB.verifiedUsers) userDB.verifiedUsers = {};
  if (!userDB.deauthorizedUsers) userDB.deauthorizedUsers = {};
  if (!userDB.statistics) {
    userDB.statistics = {
      totalVerified: 0,
      verificationsByDay: {},
      failedAttempts: 0,
      totalDeauths: 0
    };
  } else if (!userDB.statistics.totalDeauths) {
    userDB.statistics.totalDeauths = 0;
  }
  log(`Database structure ensured`, 'STARTUP');
}

// Save the userDB to the file
function saveUserDB() {
  try {
    // First ensure directories exist
    ensureDatabaseDirectory();
    
    // Then write the file
    fs.writeFileSync(config.dbPath, JSON.stringify(userDB, null, 2));
    log(`Database saved to ${config.dbPath}`, 'COMPLETE');
    return true;
  } catch (error) {
    log(`Failed to save database`, 'ERROR', error);
    return false;
  }
}

// Load the userDB from the file or create a new one if it doesn't exist
function loadUserDB() {
  try {
    // Make sure our userDB is properly initialized first
    ensureUserDBStructure();
    
    // Check if file exists before trying to read it
    if (fs.existsSync(config.dbPath)) {
      try {
        const data = fs.readFileSync(config.dbPath, 'utf8');
        const parsedData = JSON.parse(data);
        
        // Update our userDB with the loaded data
        userDB = parsedData;
        
        // Still ensure structure in case loaded DB is missing fields
        ensureUserDBStructure();
        
        log(`Loaded database from ${config.dbPath} with ${Object.keys(userDB.verifiedUsers || {}).length} verified users`, 'COMPLETE');
        return true;
      } catch (readError) {
        log(`Error reading database file, using default database`, 'ERROR', readError);
        // We already initialized userDB above, so just ensure it's saved
        saveUserDB();
        return false;
      }
    } else {
      // Create the database file if it doesn't exist
      log(`Database file ${config.dbPath} not found. Creating empty database.`, 'WARN');
      saveUserDB();
      return false;
    }
  } catch (error) {
    log(`Failed to load database, using empty database`, 'ERROR', error);
    // We already initialized userDB, so just ensure it's saved
    saveUserDB();
    return false;
  }
}

// ==================== EXPRESS SERVER ====================
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

  log(`User authenticated: ${userData.username}#${userData.discriminator} (${userData.id})`, 'INFO');
  return done(null, userData);
}));

// Home page
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

// Manual approval auth route
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

        // Auth callback
app.get('/auth/callback', 
  passport.authenticate('discord', { failureRedirect: '/' }),
  async (req, res) => {
    try {
      ensureUserDBStructure();
      
      // Record verification IP if available
      if (req.user && req.session && req.session.authCode) {
        const pendingVerification = userDB.pendingVerifications[req.session.authCode];
        if (pendingVerification) {
          req.user.verificationIP = pendingVerification.ip;
          delete userDB.pendingVerifications[req.session.authCode];
        }
      }
      
      // Check if user was previously deauthorized
      const wasDeauthorized = req.user && userDB.deauthorizedUsers && userDB.deauthorizedUsers[req.user.id];
      if (wasDeauthorized) {
        // Add this information to their request data
        req.user.wasDeauthorized = true;
        req.user.previousDeauthReason = userDB.deauthorizedUsers[req.user.id].deauthorizationReason;
      }
      
      // Add user to verified database or pending approvals
      if (req.user) {
        // CHANGE: Always require manual approval for all users
        // Check if this authentication requires manual approval
        if (true) { // Always require manual approval
          // Add to pending approvals with notification flag
          req.user.notificationSent = true; // Add flag to track if notification sent
          userDB.pendingApprovals[req.user.id] = req.user;
          saveUserDB();
          
          // Notify staff for approval
          sendVerificationRequestToChannel(req.user.id, req.user.username);
          
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
          // This code is now unreachable but kept for reference
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
                  log(`Could not send welcome DM to ${req.user.username}`, 'WARN', dmError);
                }
                
                log(`User ${req.user.username} (${req.user.id}) verified and given the verified role`, 'SUCCESS');
              }
            } catch (roleError) {
              log(`Error assigning verified role`, 'ERROR', roleError);
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
      log(`Error during authentication callback`, 'ERROR', error);
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
  log(`Server running on port ${config.port}`, 'STARTUP');
});

// ==================== DISCORD BOT FUNCTIONS ====================
// Array of status messages that rotate
const statusMessages = [
  { text: '🍌 Type /verify to authenticate', type: ActivityType.Playing },
  { text: '👆 Click the verify button in #get-your-banana', type: ActivityType.Watching },
  { text: '🔑 Verify for full server access', type: ActivityType.Competing },
  { text: '❓ Need help? Ask a staff member', type: ActivityType.Listening }
];

// Track current status index
let currentStatusIndex = 0;

// Function to set and rotate presence
function setRotatingPresence() {
  const status = statusMessages[currentStatusIndex];
  
  client.user.setPresence({
    activities: [{ 
      name: status.text, 
      type: status.type 
    }],
    status: 'online'
  });
  
  // Update index for next call
  currentStatusIndex = (currentStatusIndex + 1) % statusMessages.length;
  
  log(`Bot presence updated: ${status.text}`, 'JOB');
}

// Set up rotating presence system
function setBotPresence() {
  // Set initial status
  setRotatingPresence();
  
  // Set interval to change status every 12 seconds
  setInterval(setRotatingPresence, 12000);
  
  log(`Bot presence rotation started`, 'STARTUP');
}

// Function to send verification request to the approval channel with buttons
async function sendVerificationRequestToChannel(userId, username) {
  if (!userId || !username) {
    log(`Invalid user information for approval notification`, 'WARN');
    return false;
  }
  
  try {
    const guild = client.guilds.cache.get(config.guildId);
    if (!guild) {
      log(`Guild not found: ${config.guildId}`, 'WARN');
      return false;
    }
    
    const approvalChannel = guild.channels.cache.get(config.approvalChannelId);
    if (!approvalChannel) {
      log(`Approval channel not found: ${config.approvalChannelId}`, 'WARN');
      return false;
    }
    
    // Check if user was previously deauthorized
    const wasDeauthorized = userDB.deauthorizedUsers && userDB.deauthorizedUsers[userId];
    
    // Create accept button
    const acceptButton = new ButtonBuilder()
      .setCustomId(`approve_${userId}`)
      .setLabel('✅ Accept')
      .setStyle(ButtonStyle.Success);
    
    // Create deny button
    const denyButton = new ButtonBuilder()
      .setCustomId(`deny_${userId}`)
      .setLabel('❌ Deny')
      .setStyle(ButtonStyle.Danger);
    
    // Add buttons to action row
    const actionRow = new ActionRowBuilder()
      .addComponents(acceptButton, denyButton);
    
    // Create embed
    const embed = new EmbedBuilder()
      .setTitle('🍌 Pending Verification Request')
      .setDescription(`<@${userId}> (${username}) is requesting verification.${
        wasDeauthorized 
          ? `\n\n⚠️ **Note:** This user was previously deauthorized.\n**Reason:** ${wasDeauthorized.deauthorizationReason || 'No reason provided'}` 
          : ''
      }`)
      .setColor(wasDeauthorized ? '#FF9B21' : config.embedColor) // Orange for previously deauthed users
      .setFooter({ text: config.embedFooter })
      .setTimestamp();
    
    // Send message with buttons
    await approvalChannel.send({ 
      embeds: [embed],
      components: [actionRow]
    });
    
    log(`Sent verification request to approval channel for user ${username} (${userId})`, 'JOB');
    return true;
  } catch (error) {
    log(`Error sending verification request to channel`, 'ERROR', error);
    return false;
  }
}

async function processVerificationApproval(userId, approved, staffId) {
  try {
    // Check if user is in pending approvals
    if (!userDB.pendingApprovals || !userDB.pendingApprovals[userId]) {
      log(`User ${userId} not found in pending approvals`, 'WARN');
      return false;
    }
    
    const userData = userDB.pendingApprovals[userId];
    
    if (approved) {
      // Check if user was previously deauthorized
      const wasDeauthed = userDB.deauthorizedUsers && userDB.deauthorizedUsers[userId];
      
      // Move from pending to verified
      userDB.verifiedUsers[userId] = userData;
      
      // Remove from deauthorized users if they were there
      if (wasDeauthed) {
        delete userDB.deauthorizedUsers[userId];
      }
      
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
            log(`Error fetching member ${userId}`, 'ERROR', err);
            return null;
          });
          
          if (member) {
            await member.roles.add(config.verifiedRoleId).catch(err => {
              log(`Error adding role to member ${userId}`, 'ERROR', err);
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
                    { name: 'User ID', value: userId, inline: true },
                    { name: 'Approved By', value: `<@${staffId}>`, inline: true }
                  )
                  .setColor(config.embedColor)
                  .setFooter({ text: config.embedFooter })
                  .setTimestamp();
                
                await logChannel.send({ embeds: [embed] }).catch(err => {
                  log(`Error sending log message`, 'WARN', err);
                });
              }
            }
            
            // Try to send welcome message to the user
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
              log(`Sent welcome DM to ${userData.username}`, 'SUCCESS');
            } catch (dmError) {
              log(`Could not send welcome DM to ${userData.username}`, 'WARN', dmError);
              
              // Try to record in log channel that DM failed
              if (config.logChannelId) {
                const logChannel = guild.channels.cache.get(config.logChannelId);
                if (logChannel) {
                  await logChannel.send({
                    content: `⚠️ NOTE: Could not send welcome DM to <@${userId}>. They may have DMs disabled.`
                  }).catch(err => {
                    log(`Error logging DM failure`, 'WARN', err);
                  });
                }
              }
            }
          }
        } catch (roleError) {
          log(`Error assigning verified role`, 'ERROR', roleError);
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
            .setDescription(`<@${userId}>'s verification request was denied by <@${staffId}>.`)
            .addFields(
              { name: 'Username', value: `${userData.username}#${userData.discriminator}`, inline: true },
              { name: 'User ID', value: userId, inline: true },
              { name: 'Denied By', value: `<@${staffId}>`, inline: true }
            )
            .setColor('#FF0000')
            .setFooter({ text: config.embedFooter })
            .setTimestamp();
          
          await logChannel.send({ embeds: [embed] }).catch(err => {
            log(`Error sending log message`, 'WARN', err);
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
              log(`Error sending denial notification`, 'WARN', err);
            });
          }
        }
      } catch (dmError) {
        log(`Could not send denial DM`, 'WARN', dmError);
      }
    }
    
    // Remove from pending approvals
    delete userDB.pendingApprovals[userId];
    saveUserDB();
    
    log(`User ${userId} approval processed: ${approved ? 'Approved' : 'Denied'} by ${staffId}`, approved ? 'COMPLETE' : 'DANGER');
    return true;
  } catch (error) {
    log(`Error processing approval for ${userId}`, 'ERROR', error);
    return false;
  }
}

async function checkPendingApprovals() {
  try {
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
      log(`Found ${pendingCount} pending approvals, sending notifications`, 'JOB');
      
      // Send verification requests to the approval channel
      const guild = client.guilds.cache.get(config.guildId);
      if (!guild) {
        log(`Guild not found: ${config.guildId}`, 'WARN');
        return pendingCount;
      }
      
      const approvalChannel = guild.channels.cache.get(config.approvalChannelId);
      if (!approvalChannel) {
        log(`Approval channel not found: ${config.approvalChannelId}`, 'WARN');
        return pendingCount;
      }
      
      // Send individual requests only for entries that haven't been notified yet
      for (const [userId, userData] of pendingEntries) {
        // Skip if notification was already sent
        if (userData.notificationSent) {
          continue;
        }
        
        const success = await sendVerificationRequestToChannel(userId, userData.username);
        
        if (success) {
          // Mark as notified
          userData.notificationSent = true;
          saveUserDB();
        } else {
          log(`Pausing notifications due to previous failure`, 'WARN');
          break;
        }
        
        // Add a delay between notifications to avoid rate limits
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
    return pendingCount;
  } catch (error) {
    log(`Error checking pending approvals`, 'ERROR', error);
    return 0;
  }
}

async function safeDeleteMessages(channel, messages) {
  try {
    // Filter messages to those less than 14 days old
    const twoWeeksAgo = Date.now() - 12096e5; // 14 days in milliseconds
    const recentMessages = messages.filter(msg => msg.createdTimestamp > twoWeeksAgo);
    
    if (recentMessages.size > 0) {
      await channel.bulkDelete(recentMessages).catch(err => {
        log(`Error bulk deleting recent messages`, 'WARN', err);
      });
    }
    
    // For older messages, delete them individually
    const oldMessages = messages.filter(msg => msg.createdTimestamp <= twoWeeksAgo);
    for (const [_, message] of oldMessages) {
      try {
        await message.delete().catch(err => {
          log(`Error deleting old message ${message.id}`, 'WARN', err);
        });
        // Small delay to avoid rate limits
        await new Promise(resolve => setTimeout(resolve, 1000));
      } catch (err) {
        log(`Failed to delete message ${message.id}`, 'WARN', err);
      }
    }
    return true;
  } catch (error) {
    log(`Error in message deletion process`, 'ERROR', error);
    return false;
  }
}

async function setupVerificationSystem(guild) {
  try {
    // Create or find verification category
    let category;
    if (config.verificationCategoryId) {
      category = guild.channels.cache.get(config.verificationCategoryId);
    }

    if (!category) {
      log(`Creating verification category`, 'JOB');
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
    }

    // Create or find verification channel
    let verificationChannel;
    if (config.verificationChannelId) {
      verificationChannel = guild.channels.cache.get(config.verificationChannelId);
    }

    if (!verificationChannel) {
      log(`Creating verification channel`, 'JOB');
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
      
      // Send the verification message
      await sendVerificationMessage(verificationChannel);
    }

    // Create or find log channel
    let logChannel;
    if (config.logChannelId) {
      logChannel = guild.channels.cache.get(config.logChannelId);
    }

    if (!logChannel) {
      log(`Creating log channel`, 'JOB');
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

    // Create or find approval channel
    let approvalChannel;
    if (config.approvalChannelId) {
      approvalChannel = guild.channels.cache.get(config.approvalChannelId);
    }

    if (!approvalChannel) {
      log(`Creating approval channel`, 'JOB');
      approvalChannel = await guild.channels.create({
        name: 'verification-approvals',
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
      config.approvalChannelId = approvalChannel.id;
      
      // Add permission for staff to view and interact with approval channel
      if (config.staffRoleId) {
        const staffRole = guild.roles.cache.get(config.staffRoleId);
        if (staffRole) {
          await approvalChannel.permissionOverwrites.create(staffRole, {
            ViewChannel: true,
            ReadMessageHistory: true
          });
        }
      }
      
      // Add permission for admins as well
      const adminRoles = guild.roles.cache.filter(role => 
        role.permissions.has(PermissionsBitField.Flags.Administrator)
      );
      
      for (const [_, role] of adminRoles) {
        await approvalChannel.permissionOverwrites.create(role, {
          ViewChannel: true,
          ReadMessageHistory: true
        });
      }
    }

    return { category, verificationChannel, logChannel, approvalChannel };
  } catch (error) {
    log(`Error setting up verification system`, 'ERROR', error);
    return null;
  }
}

function isStaffMember(member) {
  return member.roles.cache.has(config.staffRoleId) || 
         member.permissions.has(PermissionsBitField.Flags.Administrator);
}

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
  log(`Sent verification message to channel ${channel.id}`, 'JOB');
}

// New function to check if there's already a verification message in the specified channel
async function checkAndSendVerificationToChannel(channelId) {
  try {
    // Get the specified channel
    const guild = client.guilds.cache.get(config.guildId);
    if (!guild) {
      log(`Guild with ID ${config.guildId} not found`, 'ERROR');
      return false;
    }
    
    const channel = guild.channels.