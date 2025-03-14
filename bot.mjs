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
  // User provided credentials - REPLACE WITH YOUR ACTUAL CREDENTIALS
  clientId: 'YOUR_CLIENT_ID',
  clientSecret: 'YOUR_CLIENT_SECRET',
  token: 'YOUR_BOT_TOKEN',

  // Server configuration
  port: 20295,
  redirectUri: 'http://your-server-domain:20295/auth/callback',
  serverUrl: 'http://your-server-domain:20295',

  // Discord IDs
  guildId: 'YOUR_GUILD_ID',
  verifiedRoleId: 'VERIFIED_ROLE_ID', 
  staffRoleId: 'STAFF_ROLE_ID', 
  verificationCategoryId: 'VERIFICATION_CATEGORY_ID',
  verificationChannelId: 'VERIFICATION_CHANNEL_ID',
  logChannelId: 'LOG_CHANNEL_ID',
  additionalVerificationChannelId: 'ADDITIONAL_VERIFICATION_CHANNEL_ID', // Additional specified channel for verification
  approvalChannelId: 'APPROVAL_CHANNEL_ID', // Channel for verification approval messages

  // Session settings
  sessionSecret: 'your-session-secret',
  dbPath: './monkey-verified-users.json',

  // Branding
  embedColor: '#3eff06',
  embedFooter: '© MonkeyBytes Tech | The Code Jungle',
  welcomeMessage: "🎉 Authentication successful! Welcome to the MonkeyBytes jungle! 🌴\n\nYour verification has been approved by our staff team, and you now have full access to all our coding resources, channels, and community features.\n\n🐒 Don't be shy - introduce yourself in our community channels\n💻 Check out our code repositories and learning resources\n🍌 Enjoy your verified status and all the perks that come with it!\n\nIf you need any help, our moderator team is just a message away!",
  verificationMessage: "To join the MonkeyBytes community, you'll need to verify your account. Click the button below to begin the verification process! 🍌\n\nAfter you authenticate, a staff member will review and approve your request.\n\nThis verification system helps us keep our coding jungle safe and secure.",

  // Heartbeat configuration
  heartbeatWebhook: "YOUR_HEARTBEAT_WEBHOOK_URL",
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
    
    const channel = guild.channels.cache.get(channelId);
    if (!channel) {
      log(`Channel with ID ${channelId} not found`, 'ERROR');
      return false;
    }
    
    // Check if there's already a verification message with a button
    const messages = await channel.messages.fetch({ limit: 10 });
    const verificationMessages = messages.filter(msg => 
      msg.author.id === client.user.id && 
      msg.components.length > 0 &&
      msg.components[0].components.some(c => c.customId === 'verify_button')
    );
    
    // If there's already a verification message, don't send a new one
    if (verificationMessages.size > 0) {
      log(`Verification message already exists in channel ${channelId}`, 'INFO');
      return false;
    }
    
    // No verification message found, send a new one
    await sendVerificationMessage(channel);
    log(`Sent verification message to channel ${channelId}`, 'SUCCESS');
    return true;
  } catch (error) {
    log(`Error checking/sending verification message to channel ${channelId}`, 'ERROR', error);
    return false;
  }
}

async function registerCommands(guild) {
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
      
      // Staff commands - Verify and deauth
      {
        name: 'manualverify',
        description: '[Staff] Manually verify a user',
        type: ApplicationCommandType.ChatInput,
        options: [
          {
            name: 'user',
            description: 'The user to verify',
            type: 6, // USER type
            required: true
          }
        ]
      },
      {
        name: 'deauth',
        description: '[Staff] Remove verification from a user',
        type: ApplicationCommandType.ChatInput,
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
      
      // Stats command
      {
        name: 'stats',
        description: '[Staff] View verification statistics',
        type: ApplicationCommandType.ChatInput
      },
      
      // Setup command
      {
        name: 'setup',
        description: '[Staff] Setup the verification system',
        type: ApplicationCommandType.ChatInput
      },
      
      // Pending approvals command
      {
        name: 'pendingapprovals',
        description: '[Staff] View pending approvals',
        type: ApplicationCommandType.ChatInput
      },
      
      // Update verification message command
      {
        name: 'updateverifymsg',
        description: '[Staff] Update the verification message',
        type: ApplicationCommandType.ChatInput
      },
      
      // NEW: Update verification message in additional channel command
      {
        name: 'updateadditionalverifymsg',
        description: '[Staff] Update the verification message in the additional channel',
        type: ApplicationCommandType.ChatInput
      }
    ];
    
    await guild.commands.set(commandsData);
    log(`Registered ${commandsData.length} commands in guild ${guild.name}`, 'COMPLETE');
    return true;
  } catch (error) {
    log(`Error registering commands`, 'ERROR', error);
    return false;
  }
}

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

// ==================== HEARTBEAT FUNCTION ====================
async function sendHeartbeat() {
  try {
    // Get accurate counts
    const currentVerifiedCount = Object.keys(userDB.verifiedUsers || {}).length;
    const currentDeauthCount = Object.keys(userDB.deauthorizedUsers || {}).length;
    const pendingCount = Object.keys(userDB.pendingApprovals || {}).length;
    
    // Simple heartbeat with only essential information
    const heartbeatEmbed = {
      title: "🍌 MonkeyBytes Auth Status",
      color: 0x3eff06,
      timestamp: new Date().toISOString(),
      fields: [
        {
          name: "Bot Status",
          value: `Online | ${client.user.tag}`,
          inline: true
        },
        {
          name: "Memory",
          value: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`,
          inline: true
        },
        {
          name: "Verified Users",
          value: currentVerifiedCount.toString(),
          inline: true
        },
        {
          name: "Deauthorized Users",
          value: currentDeauthCount.toString(),
          inline: true
        },
        {
          name: "Pending Approvals",
          value: pendingCount.toString(),
          inline: true
        },
        {
          name: "Total Stats",
          value: `✅ ${userDB.statistics.totalVerified} verified | ❌ ${userDB.statistics.totalDeauths} deauthed`,
          inline: false
        }
      ],
      footer: {
        text: config.embedFooter
      }
    };
    
    // Send to webhook
    await axios({
      method: 'post',
      url: config.heartbeatWebhook,
      headers: {
        'Content-Type': 'application/json',
      },
      data: {
        username: "MonkeyBytes Auth",
        embeds: [heartbeatEmbed]
      },
      timeout: 5000
    });
    
    log(`Heartbeat sent`, 'JOB');
  } catch (error) {
    log(`Failed to send heartbeat`, 'WARN', error);
  }
}

// ==================== BOT EVENTS ====================
client.once('ready', async () => {
  log(`Bot logged in as ${client.user.tag}`, 'STARTUP');
  
  // Set bot presence
  setBotPresence();

  // Setup verification system
  const guild = client.guilds.cache.get(config.guildId);
  if (guild) {
    await setupVerificationSystem(guild);
    await registerCommands(guild);
    log(`Verification system ready in guild: ${guild.name}`, 'COMPLETE');
    
    // Send verification message to the additional specified channel
    if (config.additionalVerificationChannelId) {
      await checkAndSendVerificationToChannel(config.additionalVerificationChannelId);
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
          log(`Found ${pendingCount} pending approvals`, 'JOB');
        }
      } catch (error) {
        log(`Error in automatic pending approval check`, 'ERROR', error);
      }
    }, 30000); // 30 seconds
  } else {
    log(`Guild with ID ${config.guildId} not found`, 'ERROR');
  }
});

// Handle button interactions
client.on('interactionCreate', async interaction => {
  try {
    // Verify button
    if (interaction.isButton()) {
      if (interaction.customId === 'verify_button') {
        // Check if user is already verified
        if (userDB.verifiedUsers && userDB.verifiedUsers[interaction.user.id]) {
          return interaction.reply({
            content: '✅ You are already verified!',
            flags: MessageFlags.Ephemeral
          });
        }
        
        return sendVerificationUrl(interaction);
      }
      
      // Handle approval buttons
      if (interaction.customId.startsWith('approve_') || interaction.customId.startsWith('deny_')) {
        // Permission check
        if (!isStaffMember(interaction.member)) {
          return interaction.reply({ 
            content: 'You need staff permissions to use these buttons.',
            flags: MessageFlags.Ephemeral
          });
        }
        
        const approved = interaction.customId.startsWith('approve_');
        const userId = interaction.customId.split('_')[1];
        
        // Process the verification
        await interaction.deferReply({ ephemeral: true });
        
        const success = await processVerificationApproval(userId, approved, interaction.user.id);
        
        if (success) {
          // Add a reaction to the message to show it's been processed
          try {
            await interaction.message.react(approved ? '✅' : '❌');
          } catch (reactError) {
            log(`Error adding reaction to message`, 'WARN', reactError);
          }
          
          // Reply to the interaction
          await interaction.editReply({
            content: `✅ Successfully ${approved ? 'approved' : 'denied'} verification for <@${userId}>.`,
          });
          
          // Edit the original message to show it's been processed and remove buttons
          const updatedEmbed = EmbedBuilder.from(interaction.message.embeds[0])
            .setTitle(approved ? '✅ Verification Approved' : '❌ Verification Denied')
            .setDescription(`<@${userId}> verification has been ${approved ? 'approved' : 'denied'} by <@${interaction.user.id}>.`)
            .setColor(approved ? config.embedColor : '#FF0000')
            .setTimestamp();
          
          // Update message without any components (buttons)
          await interaction.message.edit({ 
            embeds: [updatedEmbed],
            components: [] // Remove all buttons
          });
        } else {
          await interaction.editReply({
            content: `❌ Error processing ${approved ? 'approval' : 'denial'}. The user might no longer be pending.`,
          });
        }
        
        return;
      }
    }
    
    // Handle slash commands
    if (interaction.isChatInputCommand()) {
      const { commandName } = interaction;
      
      // Public verify command
      if (commandName === 'verify') {
        // Check if user is already verified
        if (userDB.verifiedUsers && userDB.verifiedUsers[interaction.user.id]) {
          return interaction.reply({
            content: '✅ You are already verified!',
            flags: MessageFlags.Ephemeral
          });
        }
        
        return sendVerificationUrl(interaction);
      }
      
      // Manual verify command
      else if (commandName === 'manualverify') {
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
            log(`Error fetching member for manual verification: ${user.id}`, 'ERROR', err);
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
          
          saveUserDB();
          
          // Add the verified role
          await member.roles.add(config.verifiedRoleId).catch(err => {
            log(`Error adding verified role to ${user.id}`, 'ERROR', err);
            throw new Error(`Could not add verified role: ${err.message}`);
          });
          
          // Log the verification
          const logChannel = interaction.guild.channels.cache.get(config.logChannelId);
          if (logChannel) {
            const embed = new EmbedBuilder()
              .setTitle('🍌 User Manually Verified')
              .setDescription(`<@${user.id}> has been manually verified by <@${interaction.user.id}>!`)
              .addFields([
                { name: 'Username', value: `${user.username}#${user.discriminator}`, inline: true },
                { name: 'User ID', value: user.id, inline: true },
                { name: 'Verified By', value: `<@${interaction.user.id}>`, inline: true }
              ])
              .setColor(config.embedColor)
              .setFooter({ text: config.embedFooter })
              .setTimestamp();
            
            await logChannel.send({ embeds: [embed] }).catch(err => {
              log(`Error sending log message for manual verification`, 'WARN', err);
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
            log(`Sent welcome DM to ${user.username}`, 'SUCCESS');
          } catch (dmError) {
            log(`Could not send welcome DM to ${user.username}`, 'WARN', dmError);
            
            // Log to the log channel that DM failed
            if (config.logChannelId) {
              const logChannel = interaction.guild.channels.cache.get(config.logChannelId);
              if (logChannel) {
                await logChannel.send({
                  content: `⚠️ NOTE: Could not send welcome DM to <@${user.id}>. They may have DMs disabled.`,
                  allowedMentions: { users: [] } // Prevent pinging the user
                }).catch(err => {
                  log(`Error logging DM failure`, 'WARN', err);
                });
              }
            }
          }
          
          await interaction.reply({ 
            content: `✅ Successfully verified <@${user.id}> and assigned the verified role.`,
            flags: MessageFlags.Ephemeral
          });
        } catch (error) {
          log(`Error during manual verification for ${user.id}`, 'ERROR', error);
          await interaction.reply({
            content: `❌ Error verifying user: ${error.message}`,
            flags: MessageFlags.Ephemeral
          });
        }
      }
      
      // Deauth command
      else if (commandName === 'deauth') {
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
        if (!userDB || !userDB.verifiedUsers || !userDB.verifiedUsers[user.id]) {
          return interaction.editReply({ 
            content: `❌ User <@${user.id}> is not verified.`
          });
        }
        
        try {
          // Get the member object
          const member = await interaction.guild.members.fetch(user.id).catch(err => {
            log(`Error fetching member for deauth: ${user.id}`, 'ERROR', err);
            return null;
          });
          
          // Remove user from verified database
          delete userDB.verifiedUsers[user.id];
          
          // Add to deauthorized users list
          userDB.deauthorizedUsers[user.id] = {
            ...userDB.verifiedUsers[user.id],
            deauthorizedAt: new Date().toISOString(),
            deauthorizedBy: interaction.user.id,
            deauthorizationReason: reason
          };
          
          // Update statistics
          userDB.statistics.totalDeauths++;
          
          saveUserDB();
          
          // If the member is still in the server, remove their role and send notification
          if (member) {
            // Remove the verified role if they have it
            if (member.roles.cache.has(config.verifiedRoleId)) {
              await member.roles.remove(config.verifiedRoleId).catch(err => {
                log(`Error removing verified role from ${user.id}`, 'ERROR', err);
                // Continue even if role removal fails - we've already removed from DB
              });
            }
            
            // Try to send DM to user with verification link
            let dmSuccess = false;
            try {
              const authUrl = `${config.serverUrl}/auth`;
              const embed = new EmbedBuilder()
                .setTitle('🐵 MonkeyBytes Verification Status Update')
                .setDescription(`Your verification access to the MonkeyBytes server has been revoked by a staff member.\n\n**Reason:** ${reason}\n\nTo regain access to our coding jungle, please [click here to verify again](${authUrl}). After you authenticate, a staff member will review your request.\n\nIf you have any questions about this decision, please contact a server administrator.`)
                .setColor('#FF9B21') // Orange for warnings
                .setFooter({ text: config.embedFooter })
                .setTimestamp();
              
              await user.send({ embeds: [embed] });
              dmSuccess = true;
              log(`Sent deauth DM to ${user.username}`, 'INFO');
            } catch (dmError) {
              log(`Could not send deauth DM to ${user.username}`, 'WARN', dmError);
              dmSuccess = false;
            }
            
            // If DM failed, log to the log channel
            if (!dmSuccess && config.logChannelId) {
              const logChannel = interaction.guild.channels.cache.get(config.logChannelId);
              if (logChannel) {
                await logChannel.send({
                  content: `⚠️ NOTE: Could not send deauthorization notification DM to <@${user.id}>. They may have DMs disabled.`,
                  allowedMentions: { users: [] } // Prevent pinging the user
                }).catch(err => {
                  log(`Error logging DM failure`, 'WARN', err);
                });
              }
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
              log(`Error sending log message for deauth command`, 'WARN', err);
            });
          }
          
          await interaction.editReply({ 
            content: `✅ Successfully deauthorized <@${user.id}>. ${member ? "They have been sent a reauthorization link." : "User is no longer in the server but their verification data has been removed."}`
          });
        } catch (error) {
          log(`Error during deauthorization for ${user.id}`, 'ERROR', error);
          await interaction.editReply({ 
            content: `❌ Error deauthorizing user: ${error.message}`
          });
        }
      }
      
      // Stats command
      else if (commandName === 'stats') {
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
        const deauthCount = Object.keys(userDB.deauthorizedUsers || {}).length;
        
        const embed = new EmbedBuilder()
          .setTitle('🍌 MonkeyBytes Verification Stats')
          .addFields(
            { name: 'Currently Verified', value: Object.keys(userDB.verifiedUsers).length.toString(), inline: true },
            { name: 'Total Verifications', value: stats.totalVerified.toString(), inline: true },
            { name: 'Deauthorized Users', value: deauthCount.toString(), inline: true },
            { name: 'Pending Approvals', value: pendingCount.toString(), inline: true },
            { name: 'Failed Attempts', value: stats.failedAttempts.toString(), inline: true }
          )
          .setColor(config.embedColor)
          .setFooter({ text: config.embedFooter })
          .setTimestamp();
        
        // Add today's verifications
        const today = new Date().toISOString().split('T')[0];
        const todayVerifications = stats.verificationsByDay[today] || 0;
        embed.addFields(
          { name: 'Verifications Today', value: todayVerifications.toString() }
        );
        
        // Create a button to trigger manual check for pending approvals
        const checkButton = new ButtonBuilder()
          .setCustomId('check_pending_approvals')
          .setLabel('Check Pending Approvals')
          .setStyle(ButtonStyle.Primary);
        
        const row = new ActionRowBuilder().addComponents(checkButton);
        
        await interaction.reply({ embeds: [embed], components: [row], flags: MessageFlags.Ephemeral });
      }
      
      // Setup command
      else if (commandName === 'setup') {
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
            content: `✅ Setup complete! Verification channel: <#${channels.verificationChannel.id}>, Log channel: <#${channels.logChannel.id}>, Approval channel: <#${channels.approvalChannel.id}>`
          });
        } else {
          await interaction.editReply({ 
            content: `❌ Error setting up verification system. Check console logs.`
          });
        }
      }
      
      // Pending approvals command
      else if (commandName === 'pendingapprovals') {
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
          embed.addFields([
            { 
              name: `${userData.username || 'Unknown'}#${userData.discriminator || '0'}`,
              value: `ID: ${userId}\nRequested: ${created}`,
              inline: true
            }
          ]);
          
          count++;
        }
        
        // Create a button to send DM notifications
        const notifyButton = new ButtonBuilder()
          .setCustomId('check_pending_approvals')
          .setLabel('Send Channel Notifications')
          .setStyle(ButtonStyle.Primary);
        
        const row = new ActionRowBuilder().addComponents(notifyButton);
        
        await interaction.editReply({
          embeds: [embed],
          components: [row]
        });
      }
      
      // Update verification message command
      else if (commandName === 'updateverifymsg') {
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
          log(`Error fetching messages from verification channel`, 'ERROR', err);
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
            log(`Error sending new verification message`, 'ERROR', error);
            await interaction.editReply({
              content: `❌ Error sending new verification message: ${error.message}`
            });
          }
        } else {
          await interaction.editReply({
            content: '❌ Error deleting old messages. Try again later.'
          });
        }
      }
      
      // NEW: Update verification message in additional channel command
      else if (commandName === 'updateadditionalverifymsg') {
        // Permission check
        if (!isStaffMember(interaction.member)) {
          return interaction.reply({ 
            content: 'You need staff permissions to use this command.',
            flags: MessageFlags.Ephemeral
          });
        }
        
        await interaction.deferReply({ flags: MessageFlags.Ephemeral });
        
        const additionalChannel = interaction.guild.channels.cache.get(config.additionalVerificationChannelId);
        if (!additionalChannel) {
          return interaction.editReply({
            content: '❌ Additional verification channel not found.'
          });
        }
        
        // Fetch messages for deletion with error handling
        const messages = await additionalChannel.messages.fetch({ limit: 10 }).catch(err => {
          log(`Error fetching messages from additional verification channel`, 'ERROR', err);
          return null;
        });
        
        if (!messages) {
          return interaction.editReply({
            content: '❌ Error fetching messages from additional verification channel.'
          });
        }
        
        const botMessages = messages.filter(msg => msg.author.id === client.user.id);
        
        // Use our safer delete function
        const deleteSuccess = await safeDeleteMessages(additionalChannel, botMessages);
        
        if (deleteSuccess) {
          // Send new verification message
          try {
            await sendVerificationMessage(additionalChannel);
            
            await interaction.editReply({
              content: '✅ Verification message in additional channel updated successfully!'
            });
          } catch (error) {
            log(`Error sending new verification message to additional channel`, 'ERROR', error);
            await interaction.editReply({
              content: `❌ Error sending new verification message: ${error.message}`
            });
          }
        } else {
          await interaction.editReply({
            content: '❌ Error deleting old messages. Try again later.'
          });
        }
      }
    }
    
    // Handle context menu commands
    if (interaction.isUserContextMenuCommand()) {
      const { commandName } = interaction;
      
      // Verify with MonkeyBytes context menu
      if (commandName === 'Verify with MonkeyBytes') {
        return sendVerificationUrl(interaction);
      }
    }
  } catch (error) {
    log(`Error in interaction handler`, 'ERROR', error);
    // Try to send an error message if possible
    if (interaction.replied || interaction.deferred) {
      await interaction.editReply({
        content: `❌ An error occurred while processing your command. Please try again later.`,
        flags: MessageFlags.Ephemeral
      }).catch(() => {});
    } else {
      await interaction.reply({
        content: `❌ An error occurred while processing your command. Please try again later.`,
        flags: MessageFlags.Ephemeral
      }).catch(() => {});
    }
  }
});

// ==================== BUTTON HANDLER ====================
client.on('interactionCreate', async interaction => {
  if (!interaction.isButton()) return;
  
  if (interaction.customId === 'check_pending_approvals') {
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
        log(`Error generating pending list`, 'ERROR', error);
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
});

// ==================== ERROR HANDLING ====================
process.on('uncaughtException', (error) => {
  log(`Uncaught Exception: ${error.message}`, 'FATAL', error);
  // Don't exit, just log
});

process.on('unhandledRejection', (reason) => {
  log(`Unhandled Rejection`, 'ERROR', reason);
  // Don't exit, just log
});

// ==================== INITIALIZATION ====================
// Ensure user database is properly loaded or created before continuing
ensureDatabaseDirectory();
ensureUserDBStructure();
loadUserDB();
log('Database initialization complete', 'STARTUP');

// Login to Discord
client.login(config.token).then(() => {
  log('Bot successfully logged in to Discord', 'COMPLETE');
}).catch(error => {
  log('Failed to log in to Discord', 'FATAL', error);
  
  // Try to restart after delay if login fails
  setTimeout(() => {
    log('Attempting to reconnect...', 'STARTUP');
    client.login(config.token).catch(reconnectError => {
      log('Reconnection attempt failed', 'FATAL', reconnectError);
    });
  }, 30000); // Wait 30 seconds before retry
});

// End of monkeybytes-auth-bot.mjs.