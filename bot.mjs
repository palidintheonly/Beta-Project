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
  redirectUri: 'http://your-domain.com:20295/auth/callback',
  serverUrl: 'http://your-domain.com:20295',

  // Discord IDs
  guildId: 'YOUR_GUILD_ID',
  verifiedRoleId: 'YOUR_VERIFIED_ROLE_ID', 
  staffRoleId: 'YOUR_STAFF_ROLE_ID', 
  verificationCategoryId: 'YOUR_VERIFICATION_CATEGORY_ID',
  verificationChannelId: 'YOUR_VERIFICATION_CHANNEL_ID',
  logChannelId: 'YOUR_LOG_CHANNEL_ID',

  // Staff member ID who will receive DMs about pending approvals
  approvalStaffId: 'YOUR_STAFF_ID',

  // Session settings
  sessionSecret: 'GENERATE_RANDOM_SECRET',
  dbPath: './monkey-verified-users.json',

  // Branding
  embedColor: '#3eff06',
  embedFooter: '© MonkeyBytes Tech | The Code Jungle',
  welcomeMessage: "🎉 Welcome to the MonkeyBytes jungle! You've been verified and can now access all our coding resources and community features. Grab a banana and start coding! 🍌💻",
  verificationMessage: "To join the MonkeyBytes community, you'll need to verify your account. Click the button below to get your access banana! 🍌\n\nThis helps us keep our jungle safe from bots.",

  // Heartbeat configuration
  heartbeatWebhook: "YOUR_WEBHOOK_URL",
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
  statistics: {
    totalVerified: 0,
    verificationsByDay: {},
    failedAttempts: 0
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
  if (!userDB.statistics) {
    userDB.statistics = {
      totalVerified: 0,
      verificationsByDay: {},
      failedAttempts: 0
    };
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
      
      // Add user to verified database or pending approvals
      if (req.user) {
        // CHANGE: Always require manual approval for all users
        // Check if this authentication requires manual approval
        if (true) { // Always require manual approval
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
function setBotPresence() {
  client.user.setPresence({
    activities: [{ 
      name: '🍌 Verifying Monkeys', 
      type: ActivityType.Watching 
    }],
    status: 'online'
  });
  log(`Bot presence set`, 'STARTUP');
}

async function notifyStaffForApproval(userId, username) {
  if (!userId || !username) {
    log(`Invalid user information for approval notification`, 'WARN');
    return false;
  }
  
  try {
    const staffUser = client.users.cache.get(config.approvalStaffId);
    if (!staffUser) {
      log(`Staff user for approvals not found: ${config.approvalStaffId}`, 'WARN');
      return false;
    }
    
    try {
      await staffUser.send(`**Pending Approval for:** <@${userId}> (${username})\n\nPlease respond with "yes" to approve or "no" to deny.`);
      log(`Sent approval notification to staff for user ${username} (${userId})`, 'JOB');
      return true;
    } catch (dmError) {
      log(`Failed to send DM to staff`, 'WARN', dmError);
      return false;
    }
  } catch (error) {
    log(`Error sending approval notification`, 'ERROR', error);
    return false;
  }
}

async function processVerificationApproval(userId, approved) {
  try {
    // Check if user is in pending approvals
    if (!userDB.pendingApprovals || !userDB.pendingApprovals[userId]) {
      log(`User ${userId} not found in pending approvals`, 'WARN');
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
                    { name: 'User ID', value: userId, inline: true }
                  )
                  .setColor(config.embedColor)
                  .setFooter({ text: config.embedFooter })
                  .setTimestamp();
                
                await logChannel.send({ embeds: [embed] }).catch(err => {
                  log(`Error sending log message`, 'WARN', err);
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
              log(`Could not send welcome DM to ${userData.username}`, 'WARN', dmError);
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
            .setDescription(`<@${userId}>'s verification request was denied by staff.`)
            .addFields(
              { name: 'Username', value: `${userData.username}#${userData.discriminator}`, inline: true },
              { name: 'User ID', value: userId, inline: true }
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
    
    log(`User ${userId} approval processed: ${approved ? 'Approved' : 'Denied'}`, approved ? 'COMPLETE' : 'DANGER');
    return true;
  } catch (error) {
    log(`Error processing approval for ${userId}`, 'ERROR', error);
    return false;
  }
}

// Additional functions and implementation continue...
// The rest of the code follows the same pattern as above

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
      log('Reconnection failed', 'FATAL', reconnectError);
    });
  }, 30000); // Wait 30 seconds before retry
});

// End of monkeybytes-auth-bot.mjs