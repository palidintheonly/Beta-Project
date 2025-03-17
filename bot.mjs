// monkeybytes-auth-bot.mjs
// Simple Discord Authentication Bot for MonkeyBytes

import { Client, GatewayIntentBits, EmbedBuilder, ButtonBuilder, ActionRowBuilder, 
  ButtonStyle, PermissionsBitField, ActivityType, ApplicationCommandType,
  ModalBuilder, TextInputBuilder, TextInputStyle } from 'discord.js';
import express from 'express';
import session from 'express-session';
import passport from 'passport';
import { Strategy } from 'passport-discord';
import fs from 'fs';
import path from 'path';
import { exec } from 'child_process';

// ==================== CONFIGURATION ====================
const config = {
  // Discord Application Settings
  clientId: 'YOUR_DISCORD_CLIENT_ID',           // Discord Application ID
  clientSecret: 'YOUR_DISCORD_CLIENT_SECRET',   // Discord Application Secret
  token: 'YOUR_DISCORD_BOT_TOKEN',              // Discord Bot Token
  
  // Web Server Settings
  port: 4010,                                   // Port the authentication web server runs on
  redirectUri: 'http://your-server-url:4010/auth/callback', // OAuth redirect URL
  serverUrl: 'http://your-server-url:4010',     // Public URL of the authentication server
  sessionSecret: 'YOUR_SESSION_SECRET',         // Secret for session encryption
  
  // Discord Server Settings
  guildId: 'YOUR_GUILD_ID',                     // Discord Server ID
  
  // Role IDs
  verifiedRoleId: 'YOUR_VERIFIED_ROLE_ID',      // Role given to verified members
  staffRoleId: 'YOUR_STAFF_ROLE_ID',            // Role for staff members who can approve verifications
  
  // Channel IDs - Create these channels in your Discord server
  verificationCategoryId: 'YOUR_CATEGORY_ID',   // Category for verification-related channels
  verificationChannelId: 'YOUR_VERIFY_CHANNEL_ID', // Channel where users click to verify
  logChannelId: 'YOUR_LOG_CHANNEL_ID',          // Channel for logging verification events
  approvalChannelId: 'YOUR_APPROVAL_CHANNEL_ID', // Channel where staff approve verification requests
  heartbeatChannelId: 'YOUR_HEARTBEAT_CHANNEL_ID', // Channel for bot status updates
  uptimeLogsChannelId: 'YOUR_UPTIME_LOGS_CHANNEL_ID', // Channel for bot uptime/downtime logs
  resourcesChannelId: 'YOUR_RESOURCES_CHANNEL_ID', // Channel where resources are stored
  
  // Database Settings
  dbPath: './monkey-verified-users.json',       // Local database file path
  
  // Visual Settings
  embedColor: '#3eff06',                        // Color for Discord embeds
  embedFooter: '© MonkeyBytes Tech | The Royal Court', // Footer for Discord embeds
  
  // Message Templates
  welcomeMessage: "🎉 Thou hast received thy Royal Seal! Welcome to the MonkeyBytes kingdom! 🏰\n\nThy verification hath been approved by our noble Lords, and thou now haveth full access to all our coding chambers, royal halls, and the great assembly of knights.\n\n🛡️ Be not shy - introduce thyself to the other nobles in our assembly halls\n💻 Explore our code repositories and learning resources in the royal archives\n📜 Enjoy thy verified status and all the realm privileges that come with it!\n\nIf thou requireth assistance navigating the corridors of knowledge, our royal guides are but a message away!",
  verificationMessage: "To join the MonkeyBytes court, thou must obtain thy Royal Seal. Click upon the button below to begin the verification process! 📜\n\nAfter thou hast authenticated, a Lord of the realm shall review and approve thy request.\n\nThis verification process helpeth us keep our coding kingdom safe from curious knaves and mischievous rogues.",
  
  // Timing Settings
  heartbeatInterval: 630000, // 10.5 minutes between status updates
};

// ==================== GLOBAL VARIABLES ====================
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.DirectMessages
  ]
});

let userDB = {
  pendingVerifications: {},
  pendingApprovals: {},
  verifiedUsers: {},
  deauthorizedUsers: {},
  statistics: {
    totalVerified: 0,
    verificationsByDay: {},
    failedAttempts: 0,
    totalDeauths: 0
  }
};

const resourceEntries = {};
const botStartTime = new Date();
const downtimeFilePath = './monkey-uptime-history.json';
const RESTART_SIGNAL_FILE = './restart.signal';
const STOP_SIGNAL_FILE = './stop.signal';

// ==================== LOGGER ====================
const logger = {
  log: (message, level = 'INFO', error = null) => {
    const timestamp = new Date().toISOString().replace('T', ' ').substr(0, 23);
    let colorCode = '';
    
    // Google-style colors
    switch(level) {
      case 'INFO':
        colorCode = '\x1b[34m'; // Blue
        break;
      case 'WARN':
        colorCode = '\x1b[33m'; // Yellow
        break;
      case 'ERROR':
        colorCode = '\x1b[31m'; // Red
        break;
      case 'SUCCESS':
        colorCode = '\x1b[32m'; // Green
        break;
      case 'STARTUP':
        colorCode = '\x1b[35m'; // Magenta
        break;
      case 'COMMAND':
        colorCode = '\x1b[36m'; // Cyan
        break;
      default:
        colorCode = '\x1b[37m'; // White
    }
    
    // Google-style logging format with colors
    console.log(`${colorCode}[${level}] ${timestamp}\x1b[0m ${message}`);
    if (error) console.error(`\x1b[31m[ERROR DETAILS]\x1b[0m`, error);
    return true;
  },
  info: (msg, err) => logger.log(msg, 'INFO', err),
  warn: (msg, err) => logger.log(msg, 'WARN', err),
  error: (msg, err) => logger.log(msg, 'ERROR', err),
  success: (msg, err) => logger.log(msg, 'SUCCESS', err),
  startup: (msg, err) => logger.log(msg, 'STARTUP', err),
  command: (msg, err) => logger.log(msg, 'COMMAND', err)
};

// ==================== HTML TEMPLATES ====================
const htmlTemplates = {
  wrapper: (content, title, color) => `
    <html>
      <head>
        <title>${title}</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; margin: 50px; background-color: #2c2f33; color: white; }
          .icon { color: ${color}; font-size: 80px; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; background-color: #36393f; border-radius: 10px; }
          h1 { color: ${color}; }
          .button { display: inline-block; background: #FF9B21; color: white; padding: 10px 20px; 
                   text-decoration: none; border-radius: 5px; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="container">
          ${content}
        </div>
      </body>
    </html>
  `,
  
  homePage: () => htmlTemplates.wrapper(`
    <h1>MonkeyBytes Royal Authentication</h1>
    <p>Click the button below to receive thy Royal Seal and access the coding kingdom!</p>
    <a href="/auth" class="button">Receive Thy Royal Seal 📜</a>
  `, 'MonkeyBytes Royal Authentication', '#FF9B21'),
  
  pendingPage: () => htmlTemplates.wrapper(`
    <div class="icon">⏳</div>
    <h1>Awaiting Royal Approval</h1>
    <p>Thy request to join the MonkeyBytes realm hath been sent to the Lords for approval.</p>
    <p>Thou shalt be notified once they have reviewed thy petition!</p>
    <p>Thou may close this window and return to Discord.</p>
  `, 'Awaiting Royal Approval', '#FFA500'),
  
  successPage: () => htmlTemplates.wrapper(`
    <div class="icon">✓</div>
    <h1>Thou Hast Received Thy Royal Seal!</h1>
    <p>Thou hast been verified and may now access the MonkeyBytes realm!</p>
    <p>Thou may close this window and return to Discord.</p>
  `, 'Verification Successful', '#4CAF50'),
  
  errorPage: () => htmlTemplates.wrapper(`
    <div class="icon">❌</div>
    <h1>Royal Authentication Error</h1>
    <p>Alas! The royal seal hath slipped. An error occurred during the verification process.</p>
    <p>If this problem persisteth, pray contact a Lord (server administrator).</p>
  `, 'Royal Authentication Error', '#FF5555'),
  
  serverErrorPage: () => htmlTemplates.wrapper(`
    <div class="icon">❌</div>
    <h1>Royal Server Error</h1>
    <p>The nobles are having technical difficulties. Pray try again later!</p>
  `, 'Royal Server Error', '#FF5555')
};

// ==================== DATABASE FUNCTIONS ====================
function ensureDatabaseDirectory() {
  try {
    const dbDir = path.dirname(config.dbPath);
    if (dbDir !== '.' && !fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }
    return true;
  } catch (error) {
    logger.error(`Failed to create database directory`, error);
    return false;
  }
}

function ensureUserDBStructure() {
  if (!userDB) userDB = {};
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
  }
}

function saveUserDB() {
  try {
    ensureDatabaseDirectory();
    fs.writeFileSync(config.dbPath, JSON.stringify(userDB, null, 2));
    return true;
  } catch (error) {
    logger.error(`Failed to save database`, error);
    return false;
  }
}

function loadUserDB() {
  try {
    ensureUserDBStructure();
    if (fs.existsSync(config.dbPath)) {
      try {
        const data = fs.readFileSync(config.dbPath, 'utf8');
        userDB = JSON.parse(data);
        ensureUserDBStructure();
        return true;
      } catch (readError) {
        logger.error(`Error reading database file`, readError);
        saveUserDB();
        return false;
      }
    } else {
      logger.warn(`Database file not found. Creating empty database.`);
      saveUserDB();
      return false;
    }
  } catch (error) {
    logger.error(`Failed to load database`, error);
    saveUserDB();
    return false;
  }
}

// ==================== EXPRESS SERVER ====================
const app = express();

app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

app.use(session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false,
    maxAge: 60000 * 60 * 24,
    httpOnly: true,
    sameSite: 'lax'
  }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, userDB.verifiedUsers[id] || null));

passport.use(new Strategy({
  clientID: config.clientId,
  clientSecret: config.clientSecret,
  callbackURL: config.redirectUri,
  scope: ['identify', 'email', 'guilds.join']
}, (accessToken, refreshToken, profile, done) => {
  const userData = {
    id: profile.id,
    username: profile.username,
    discriminator: profile.discriminator || '0',
    globalName: profile.global_name || profile.username,
    avatar: profile.avatar,
    email: profile.email,
    accessToken,
    refreshToken,
    verifiedAt: new Date().toISOString(),
    vassalage: 1,
    tier: "knight"
  };
  
  logger.info(`User authenticated: ${userData.username}#${userData.discriminator} (${userData.id})`);
  return done(null, userData);
}));

app.get('/', (_req, res) => res.send(htmlTemplates.homePage()));

app.get('/auth', (req, _res, next) => {
  const authCode = Math.random().toString(36).substring(2, 15);
  userDB.pendingVerifications[authCode] = {
    timestamp: new Date().toISOString()
  };
  saveUserDB();
  req.session.authCode = authCode;
  next();
}, passport.authenticate('discord'));

app.get('/auth/callback', 
  passport.authenticate('discord', { failureRedirect: '/' }),
  async (req, res) => {
    try {
      ensureUserDBStructure();
      
      if (req.user && req.session && req.session.authCode) {
        if (userDB.pendingVerifications[req.session.authCode]) {
          delete userDB.pendingVerifications[req.session.authCode];
        }
      }
      
      const wasDeauthorized = req.user && userDB.deauthorizedUsers && userDB.deauthorizedUsers[req.user.id];
      if (wasDeauthorized) {
        req.user.wasDeauthorized = true;
        req.user.previousDeauthReason = userDB.deauthorizedUsers[req.user.id].deauthorizationReason;
      }
      
      if (req.user) {
        req.user.notificationSent = true;
        userDB.pendingApprovals[req.user.id] = req.user;
        saveUserDB();
        
        await sendVerificationRequestToChannel(req.user.id, req.user.username);
        return res.send(htmlTemplates.pendingPage());
      }
      
      res.send(htmlTemplates.successPage());
    } catch (error) {
      logger.error(`Error during authentication callback`, error);
      res.status(500).send(htmlTemplates.errorPage());
    }
  }
);

app.get('/status', (req, res) => {
  const clientIp = req.ip || req.socket.remoteAddress;
  const isLocalRequest = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp.startsWith('192.168.');
  
  if (isLocalRequest) {
    res.json({
      status: 'ok',
      timestamp: Date.now(),
      uptime: process.uptime(),
      memory: {
        heapUsed: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        rss: Math.round(process.memoryUsage().rss / 1024 / 1024),
      },
      stats: {
        verifiedUsers: Object.keys(userDB.verifiedUsers || {}).length,
        pendingUsers: Object.keys(userDB.pendingApprovals || {}).length
      }
    });
  } else {
    res.json({ status: 'ok', timestamp: Date.now() });
  }
});

app.use((err, _req, res, _next) => {
  logger.error('Express server error', err);
  res.status(500).send(htmlTemplates.serverErrorPage());
});

// ==================== DISCORD BOT FUNCTIONS ====================
function setRotatingPresence() {
  const statusMessages = [
    { text: '📜 Type /help for royal guidance', type: ActivityType.Playing },
    { text: '👆 Click for a royal seal in #verify', type: ActivityType.Watching },
    { text: '🔑 Get verified for full realm access', type: ActivityType.Competing },
    { text: '❓ Lost? Use /help command', type: ActivityType.Listening }
  ];
  
  let currentStatusIndex = 0;
  
  function updateStatus() {
    const status = statusMessages[currentStatusIndex];
    client.user.setPresence({
      activities: [{ name: status.text, type: status.type }],
      status: 'online'
    });
    currentStatusIndex = (currentStatusIndex + 1) % statusMessages.length;
  }
  
  updateStatus();
  setInterval(updateStatus, 12000);
}

async function sendVerificationRequestToChannel(userId, username) {
  if (!userId || !username) return false;
  
  try {
    const guild = client.guilds.cache.get(config.guildId);
    if (!guild) return false;
    
    const approvalChannel = guild.channels.cache.get(config.approvalChannelId);
    if (!approvalChannel) return false;
    
    const wasDeauthorized = userDB.deauthorizedUsers && userDB.deauthorizedUsers[userId];
    
    const acceptButton = new ButtonBuilder()
      .setCustomId(`approve_${userId}`)
      .setLabel('✅ Grant Royal Seal')
      .setStyle(ButtonStyle.Success);
    
    const denyButton = new ButtonBuilder()
      .setCustomId(`deny_${userId}`)
      .setLabel('❌ Deny')
      .setStyle(ButtonStyle.Danger);
    
    const actionRow = new ActionRowBuilder()
      .addComponents(acceptButton, denyButton);
    
    const embed = new EmbedBuilder()
      .setTitle('📜 Pending Royal Seal Request')
      .setDescription(`<@${userId}> (${username}) seeketh to join the royal court.${
        wasDeauthorized 
          ? `\n\n⚠️ **Note:** This noble previously had their royal seal revoked.\n**Reason:** ${wasDeauthorized.deauthorizationReason || 'No reason provided'}` 
          : ''
      }`)
      .setColor(wasDeauthorized ? '#FF9B21' : config.embedColor)
      .setFooter({ text: config.embedFooter })
      .setTimestamp();
    
    await approvalChannel.send({ embeds: [embed], components: [actionRow] });
    return true;
  } catch (error) {
    logger.error(`Error sending verification request`, error);
    return false;
  }
}

async function processVerificationApproval(userId, approved, staffId) {
  try {
    if (!userDB.pendingApprovals || !userDB.pendingApprovals[userId]) {
      return false;
    }
    
    const userData = userDB.pendingApprovals[userId];
    
    if (approved) {
      const wasDeauthed = userDB.deauthorizedUsers && userDB.deauthorizedUsers[userId];
      
      userDB.verifiedUsers[userId] = userData;
      
      if (wasDeauthed) {
        delete userDB.deauthorizedUsers[userId];
      }
      
      userDB.statistics.totalVerified++;
      const today = new Date().toISOString().split('T')[0];
      userDB.statistics.verificationsByDay[today] = 
        (userDB.statistics.verificationsByDay[today] || 0) + 1;
      
      const guild = client.guilds.cache.get(config.guildId);
      if (guild) {
        try {
          const member = await guild.members.fetch(userId).catch(() => null);
          
          if (member) {
            await member.roles.add(config.verifiedRoleId).catch(err => {
              logger.error(`Error adding role to member ${userId}`, err);
            });
            
            // Log the verification
            const logChannel = guild.channels.cache.get(config.logChannelId);
            if (logChannel) {
              const embed = new EmbedBuilder()
                .setTitle('📜 New Noble in the Realm')
                .setDescription(`<@${userId}> hath been granted a royal seal after lordly approval!`)
                .addFields(
                  { name: 'Noble Name', value: `${userData.username}#${userData.discriminator}`, inline: true },
                  { name: 'Noble ID', value: userId, inline: true },
                  { name: 'Approved By', value: `<@${staffId}>`, inline: true }
                )
                .setColor(config.embedColor)
                .setFooter({ text: config.embedFooter })
                .setTimestamp();
              
              await logChannel.send({ embeds: [embed] }).catch(() => {});
            }
            
            // Send welcome message
            try {
              await member.send({
                embeds: [
                  new EmbedBuilder()
                    .setTitle('🎉 Welcome to the MonkeyBytes Realm!')
                    .setDescription(config.welcomeMessage)
                    .setColor(config.embedColor)
                    .setFooter({ text: config.embedFooter })
                ]
              });
            } catch (dmError) {
              logger.warn(`Could not send welcome DM to ${userData.username}`, dmError);
            }
          }
        } catch (roleError) {
          logger.error(`Error assigning verified role`, roleError);
        }
      }
    } else {
      // Log the denial
      const guild = client.guilds.cache.get(config.guildId);
      if (guild && config.logChannelId) {
        const logChannel = guild.channels.cache.get(config.logChannelId);
        if (logChannel) {
          const embed = new EmbedBuilder()
            .setTitle('❌ Royal Seal Request Denied')
            .setDescription(`<@${userId}>'s request to join the realm was denied by <@${staffId}>.`)
            .addFields(
              { name: 'Noble Name', value: `${userData.username}#${userData.discriminator}`, inline: true },
              { name: 'Noble ID', value: userId, inline: true },
              { name: 'Denied By', value: `<@${staffId}>`, inline: true }
            )
            .setColor('#FF0000')
            .setFooter({ text: config.embedFooter })
            .setTimestamp();
          
          await logChannel.send({ embeds: [embed] }).catch(() => {});
        }
      }
      
      // Notify the user of denial
      try {
        const guild = client.guilds.cache.get(config.guildId);
        if (guild) {
          const member = await guild.members.fetch(userId).catch(() => null);
          if (member) {
            await member.send({
              embeds: [
                new EmbedBuilder()
                  .setTitle('❌ Royal Seal Access Denied')
                  .setDescription(`Thy request to join the MonkeyBytes realm hath been declined by our Lords. If thou believest this to be a mistake in the realm, pray contact the server administrators to appeal.`)
                  .setColor('#FF0000')
                  .setFooter({ text: config.embedFooter })
              ]
            }).catch(() => {});
          }
        }
      } catch (dmError) {
        logger.warn(`Could not send denial DM`, dmError);
      }
    }
    
    delete userDB.pendingApprovals[userId];
    saveUserDB();
    
    return true;
  } catch (error) {
    logger.error(`Error processing approval for ${userId}`, error);
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
      const guild = client.guilds.cache.get(config.guildId);
      if (!guild) return pendingCount;
      
      const approvalChannel = guild.channels.cache.get(config.approvalChannelId);
      if (!approvalChannel) return pendingCount;
      
      for (const [userId, userData] of pendingEntries) {
        if (userData.notificationSent) continue;
        
        const success = await sendVerificationRequestToChannel(userId, userData.username);
        
        if (success) {
          userData.notificationSent = true;
          saveUserDB();
        } else {
          break;
        }
        
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
    return pendingCount;
  } catch (error) {
    logger.error(`Error checking pending approvals`, error);
    return 0;
  }
}

function isStaffMember(member) {
  return member.roles.cache.has(config.staffRoleId) || 
         member.permissions.has(PermissionsBitField.Flags.Administrator);
}

async function sendVerificationMessage(channel) {
  const verifyButton = new ButtonBuilder()
    .setCustomId('verify_button')
    .setLabel('📜 Receive Thy Royal Seal')
    .setStyle(ButtonStyle.Primary);

  const row = new ActionRowBuilder().addComponents(verifyButton);

  const embed = new EmbedBuilder()
    .setTitle('🛡️ MonkeyBytes Verification')
    .setDescription(config.verificationMessage)
    .setColor(config.embedColor)
    .setFooter({ text: config.embedFooter })
    .setTimestamp();

  await channel.send({ embeds: [embed], components: [row] });
}

function sendVerificationUrl(interaction) {
  const authUrl = `${config.serverUrl}/auth`;
  const embed = new EmbedBuilder()
    .setTitle('🛡️ Receive Thy Royal Seal!')
    .setDescription(`Click [here to verify](${authUrl}) thy account and join the realm.\n\nThis shall open the authentication page. After authorizing with Discord, the Lords shall review thy request.`)
    .setColor(config.embedColor)
    .setFooter({ text: config.embedFooter })
    .setTimestamp();

  return interaction.reply({ embeds: [embed], ephemeral: true });
}

// Check if database matches actual role assignments and fix discrepancies
async function syncDatabaseWithRoles() {
  try {
    const guild = client.guilds.cache.get(config.guildId);
    if (!guild) {
      logger.error("Guild not found when syncing database");
      return;
    }
    
    // Fetch all members (this may take time for large servers)
    await guild.members.fetch();
    
    // Create sets for tracking changes
    let addedToVerified = 0;
    let removedFromVerified = 0;
    
    // Check members with the role but not in database
    const membersWithRole = guild.members.cache.filter(member => 
      !member.user.bot && member.roles.cache.has(config.verifiedRoleId)
    );
    
    for (const [memberId, member] of membersWithRole) {
      // If member has role but isn't in verified list
      if (!userDB.verifiedUsers[memberId]) {
        // Add them to verified list
        userDB.verifiedUsers[memberId] = {
          id: memberId,
          username: member.user.username,
          discriminator: member.user.discriminator || '0',
          globalName: member.user.globalName || member.user.username,
          avatar: member.user.avatar,
          verifiedAt: new Date().toISOString(),
          verificationIP: 'role-sync',
          vassalage: 1,
          tier: "knight",
          manuallyVerifiedBy: 'system',
          verificationReason: 'Database sync - user had role'
        };
        
        // Remove from deauthorized if they were there
        if (userDB.deauthorizedUsers && userDB.deauthorizedUsers[memberId]) {
          delete userDB.deauthorizedUsers[memberId];
        }
        
        addedToVerified++;
      }
    }
    
    // Check users in database who don't have the role
    for (const memberId in userDB.verifiedUsers) {
      try {
        const member = await guild.members.fetch(memberId).catch(() => null);
        
        // If member exists but doesn't have the role
        if (member && !member.roles.cache.has(config.verifiedRoleId)) {
          const userData = { ...userDB.verifiedUsers[memberId] };
          
          // Move to deauthorized
          userDB.deauthorizedUsers[memberId] = {
            ...userData,
            deauthorizedAt: new Date().toISOString(),
            deauthorizedBy: 'system',
            deauthorizationReason: 'Database sync - user missing role'
          };
          
          // Remove from verified
          delete userDB.verifiedUsers[memberId];
          
          removedFromVerified++;
        }
        // If member doesn't exist in server anymore
        else if (!member) {
          const userData = { ...userDB.verifiedUsers[memberId] };
          
          // Move to deauthorized
          userDB.deauthorizedUsers[memberId] = {
            ...userData,
            deauthorizedAt: new Date().toISOString(),
            deauthorizedBy: 'system',
            deauthorizationReason: 'Database sync - user not in server'
          };
          
          // Remove from verified
          delete userDB.verifiedUsers[memberId];
          
          removedFromVerified++;
        }
      } catch (memberError) {
        logger.error(`Error syncing roles for member ${memberId}`, memberError);
      }
    }
    
    // Save changes if any were made
    if (addedToVerified > 0 || removedFromVerified > 0) {
      saveUserDB();
      logger.info(`Database sync complete: Added ${addedToVerified} users, Removed ${removedFromVerified} users`);
      
      // Log to the log channel
      const logChannel = guild.channels.cache.get(config.logChannelId);
      if (logChannel) {
        const embed = new EmbedBuilder()
          .setTitle('🔄 Royal Census Completed')
          .setDescription(`The royal record keepers have updated the realm's census.`)
          .addFields([
            { name: 'Census Results', value: `• ${addedToVerified} nobles added to royal records\n• ${removedFromVerified} nobles removed from royal records\n• ${Object.keys(userDB.verifiedUsers).length} total verified nobles in the realm`, inline: false }
          ])
          .setColor(config.embedColor)
          .setFooter({ text: config.embedFooter })
          .setTimestamp();
        
        await logChannel.send({ embeds: [embed] }).catch(() => {});
      }
    }
  } catch (error) {
    logger.error(`Error syncing database with roles`, error);
  }
}

// ==================== COMMAND REGISTRATION ====================
async function registerCommands(guild) {
  try {
    const memberCommands = [
      {
        name: 'help',
        description: 'Get help with using the MonkeyBytes server',
        type: ApplicationCommandType.ChatInput
      },
      {
        name: 'verify',
        description: 'Start the verification process for the MonkeyBytes server',
        type: ApplicationCommandType.ChatInput
      },
      {
        name: 'resources',
        description: 'View available coding resources and how to access them',
        type: ApplicationCommandType.ChatInput
      },
      {
        name: 'roles',
        description: 'View information about server roles and how to get them',
        type: ApplicationCommandType.ChatInput
      },
      {
        name: 'report',
        description: 'Report an issue to the staff team',
        type: ApplicationCommandType.ChatInput,
        options: [
          {
            name: 'issue',
            description: 'Description of the issue',
            type: 3,
            required: true
          }
        ]
      }
    ];
    
    const staffCommands = [
      {
        name: 'Verify Member',
        type: ApplicationCommandType.User
      },
      {
        name: 'Deauthorize Member',
        type: ApplicationCommandType.User
      },
      {
        name: 'View User Stats',
        type: ApplicationCommandType.User
      },
      {
        name: 'Mark as Rule Violation',
        type: ApplicationCommandType.Message
      },
      {
        name: 'Add to Resources',
        type: ApplicationCommandType.Message
      },
      {
        name: 'restart',
        description: 'Restart the bot (Staff Only)',
        type: ApplicationCommandType.ChatInput,
        options: [
          {
            name: 'reason',
            description: 'Reason for restart (optional)',
            type: 3,
            required: false
          }
        ]
      },
      {
        name: 'stop',
        description: 'Stop the bot (Staff Only)',
        type: ApplicationCommandType.ChatInput,
        options: [
          {
            name: 'reason',
            description: 'Reason for stopping the bot (optional)',
            type: 3,
            required: false
          }
        ]
      },
      {
        name: 'auth-all',
        description: 'Give the verified role to all members without it (Staff Only)',
        type: ApplicationCommandType.ChatInput,
        options: [
          {
            name: 'reason',
            description: 'Reason for mass verification (optional)',
            type: 3,
            required: false
          }
        ]
      },
      {
        name: 'deauth-all',
        description: 'Remove the verified role from all members (Staff Only)',
        type: ApplicationCommandType.ChatInput
      }
    ];
    
    await guild.commands.set([...memberCommands, ...staffCommands]);
    return true;
  } catch (error) {
    logger.error(`Error registering commands`, error);
    return false;
  }
}

// ==================== COMMAND HANDLERS ====================
// Basic command handlers
const commandHandlers = {
  help: async (interaction) => {
    const embed = new EmbedBuilder()
      .setTitle('🛡️ MonkeyBytes Royal Guide')
      .setDescription('Welcome to the coding realm! Here are some royal commands to help thee navigate:')
      .addFields(
        { name: '/help', value: 'Shows this royal guide', inline: true },
        { name: '/verify', value: 'Get thy royal seal (verification access)', inline: true },
        { name: '/resources', value: 'Discover coding treasures', inline: true },
        { name: '/roles', value: 'Learn about realm houses (roles)', inline: true },
        { name: '/report', value: 'Alert royal guards about issues', inline: true }
      )
      .setColor(config.embedColor)
      .setFooter({ text: config.embedFooter })
      .setTimestamp();

    return interaction.reply({ 
      embeds: [embed], 
      ephemeral: true
    });
  },
  
  resources: async (interaction) => {
    const embed = new EmbedBuilder()
      .setTitle('📜 Royal Court Treasures')
      .setDescription('Explore these valuable coding resources in our noble community:')
      .addFields(
        { name: '📚 Learning Corridors', value: 'Visit #beginner-help, #code-discussion, and #project-showcase to learn and share thy work.' },
        { name: '🛠️ Noble Tools', value: 'Our realm has dedicated chambers for popular frameworks and tools. Explore the channel list to find thy coding quarters.' },
        { name: '📝 Royal Archives', value: 'Check the pinned messages in each channel for valuable code snippets and preserved knowledge!' },
        { name: '🔗 Kingdom Links', value: 'Visit our website for specially curated tutorials and documentation links for noble coders of all ranks.' }
      )
      .setColor(config.embedColor)
      .setFooter({ text: config.embedFooter })
      .setTimestamp();

    return interaction.reply({ 
      embeds: [embed], 
      ephemeral: true
    });
  },
  
  roles: async (interaction) => {
    const embed = new EmbedBuilder()
      .setTitle('📜 Royal Court Roles')
      .setDescription('Discover the different houses thou can join in our coding realm:')
      .addFields(
        { name: '🔑 Verified Noble', value: 'Basic realm access. Obtained by receiving thy royal seal (verification).' },
        { name: '💻 Language Houses', value: 'Visit the #role-selection chamber to choose thy programming language houses.' },
        { name: '🏆 Experience Ranks', value: 'Show thy realm experience level in the #role-selection area.' },
        { name: '⭐ Court Guide', value: 'Awarded to active nobles who help others find their way through the code kingdom.' },
        { name: '📜 Royal Knight', value: 'Elite status for exceptionally helpful realm members. Nominated by the Lords.' }
      )
      .setColor(config.embedColor)
      .setFooter({ text: config.embedFooter })
      .setTimestamp();

    return interaction.reply({ 
      embeds: [embed], 
      ephemeral: true
    });
  },
  
  report: async (interaction) => {
    const issue = interaction.options.getString('issue');
    const user = interaction.user;
    
    const reportEmbed = new EmbedBuilder()
      .setTitle('🚨 Royal Incident Report')
      .setDescription(`A report hath been submitted by <@${user.id}>`)
      .addFields(
        { name: 'Reporting Noble', value: `${user.username}#${user.discriminator || '0'}`, inline: true },
        { name: 'Noble ID', value: user.id, inline: true },
        { name: 'Issue', value: issue }
      )
      .setColor('#FF9B21')
      .setFooter({ text: config.embedFooter })
      .setTimestamp();
    
    try {
      const guild = interaction.guild;
      const logChannel = guild.channels.cache.get(config.logChannelId);
      
      if (logChannel) {
        await logChannel.send({ embeds: [reportEmbed] });
        
        await interaction.reply({ 
          content: 'Thy alert hath been sent to the royal guards. We thank thee for helping keep our code realm safe! 🛡️', 
          ephemeral: true 
        });
      } else {
        throw new Error('Log channel not found');
      }
    } catch (error) {
      logger.error(`Error processing report`, error);
      await interaction.reply({ 
        content: 'There was a glitch in the realm. Pray contact a Lord directly.', 
        ephemeral: true 
      });
    }
  },
  
  restart: async (interaction) => {
    if (!isStaffMember(interaction.member)) {
      return interaction.reply({
        content: 'Only Lords (staff members) can use this command! 📜',
        ephemeral: true
      });
    }
    
    const reason = interaction.options.getString('reason') || 'No reason provided';
    const confirmButton = new ButtonBuilder()
      .setCustomId('confirm_restart')
      .setLabel('✅ Confirm Restart')
      .setStyle(ButtonStyle.Danger);
    
    const cancelButton = new ButtonBuilder()
      .setCustomId('cancel_restart')
      .setLabel('❌ Cancel')
      .setStyle(ButtonStyle.Secondary);
    
    const actionRow = new ActionRowBuilder().addComponents(confirmButton, cancelButton);
    
    const confirmEmbed = new EmbedBuilder()
      .setTitle('⚠️ Restart Authentication Service?')
      .setDescription(`Art thou certain thou wishest to restart the authentication service?\n\n**Reason:** ${reason}`)
      .setColor('#FF9B21')
      .setFooter({ text: 'This action shall briefly disconnect the authentication service.' })
      .setTimestamp();
    
    const message = await interaction.reply({
      embeds: [confirmEmbed],
      components: [actionRow],
      ephemeral: true
    });
    
    const response = await message.fetch();
    
    const collector = response.createMessageComponentCollector({ 
      filter: i => i.user.id === interaction.user.id,
      time: 30000
    });
    
    collector.on('collect', async i => {
      if (i.customId === 'confirm_restart') {
        await i.update({
          embeds: [
            new EmbedBuilder()
              .setTitle('🔄 Authentication Service Restarting')
              .setDescription(`The authentication service is restarting, requested by <@${interaction.user.id}>.\n\n**Reason:** ${reason}\n\nThe service shall be back online shortly.`)
              .setColor('#FF0000')
              .setTimestamp()
          ],
          components: []
        });
        
        try {
          // Log to Discord
          const guild = interaction.guild;
          const logChannel = guild.channels.cache.get(config.uptimeLogsChannelId);
          
          if (logChannel) {
            const logEmbed = new EmbedBuilder()
              .setTitle('🔄 Authentication Service Restarting')
              .setDescription(`Service restart hath been initiated by <@${interaction.user.id}>.`)
              .addFields([
                { name: 'Reason', value: reason, inline: false },
                { name: 'Time', value: new Date().toLocaleString(), inline: false }
              ])
              .setColor('#FF9B21')
              .setFooter({ text: config.embedFooter })
              .setTimestamp();
            
            await logChannel.send({ embeds: [logEmbed] });
          }
          
          saveUserDB();
          updateLastOnlineTime();
          
          // Create restart signal file
          fs.writeFileSync(RESTART_SIGNAL_FILE, `Restart requested by ${interaction.user.id} at ${new Date().toISOString()}\nReason: ${reason}`);
          
          // Simple restart using process exit
          setTimeout(() => {
            logger.info("Restarting bot with exit code 50");
            process.exit(50);  // Exit with code 50 for restart
          }, 2000);
          
        } catch (error) {
          logger.error(`Error during restart`, error);
        }
      } else if (i.customId === 'cancel_restart') {
        await i.update({
          embeds: [
            new EmbedBuilder()
              .setTitle('❌ Restart Cancelled')
              .setDescription('The authentication service shall continue running.')
              .setColor('#4CAF50')
              .setTimestamp()
          ],
          components: []
        });
      }
    });
  },
  
  stop: async (interaction) => {
    if (!isStaffMember(interaction.member)) {
      return interaction.reply({
        content: 'Only Lords (staff members) can use this command! 📜',
        ephemeral: true
      });
    }
    
    const reason = interaction.options.getString('reason') || 'No reason provided';
    const confirmButton = new ButtonBuilder()
      .setCustomId('confirm_stop')
      .setLabel('✅ Confirm Stop')
      .setStyle(ButtonStyle.Danger);
    
    const cancelButton = new ButtonBuilder()
      .setCustomId('cancel_stop')
      .setLabel('❌ Cancel')
      .setStyle(ButtonStyle.Secondary);
    
    const actionRow = new ActionRowBuilder().addComponents(confirmButton, cancelButton);
    
    const confirmEmbed = new EmbedBuilder()
      .setTitle('⚠️ Stop Authentication Service?')
      .setDescription(`Art thou certain thou wishest to stop the authentication service?\n\n**Reason:** ${reason}\n\n**⚠️ WARNING:** This shall completely shut down the service until manually restarted.`)
      .setColor('#FF0000')
      .setFooter({ text: 'This action shall disconnect the service until manually restarted.' })
      .setTimestamp();
    
    const message = await interaction.reply({
      embeds: [confirmEmbed],
      components: [actionRow],
      ephemeral: true
    });
    
    const response = await message.fetch();
    
    const collector = response.createMessageComponentCollector({ 
      filter: i => i.user.id === interaction.user.id,
      time: 30000
    });
    
    collector.on('collect', async i => {
      if (i.customId === 'confirm_stop') {
        await i.update({
          embeds: [
            new EmbedBuilder()
              .setTitle('🛑 Authentication Service Shutdown')
              .setDescription(`The authentication service is shutting down, requested by <@${interaction.user.id}>.\n\n**Reason:** ${reason}\n\nThe service shall need to be manually restarted.`)
              .setColor('#FF0000')
              .setTimestamp()
          ],
          components: []
        });
        
        try {
          // Log to Discord
          const guild = interaction.guild;
          const logChannel = guild.channels.cache.get(config.uptimeLogsChannelId);
          
          if (logChannel) {
            const logEmbed = new EmbedBuilder()
              .setTitle('🛑 Authentication Service Shutdown')
              .setDescription(`Service shutdown hath been initiated by <@${interaction.user.id}>.`)
              .addFields([
                { name: 'Reason', value: reason, inline: false },
                { name: 'Time', value: new Date().toLocaleString(), inline: false }
              ])
              .setColor('#FF0000')
              .setFooter({ text: config.embedFooter })
              .setTimestamp();
            
            await logChannel.send({ embeds: [logEmbed] });
          }
          
          saveUserDB();
          updateLastOnlineTime();
          
          // Create stop signal file
          fs.writeFileSync(STOP_SIGNAL_FILE, `Stop requested by ${interaction.user.id} at ${new Date().toISOString()}\nReason: ${reason}`);
          
          // Simple stop using process exit
          setTimeout(() => {
            logger.info("Stopping bot with clean exit");
            process.exit(0);  // Normal exit
          }, 2000);
          
        } catch (error) {
          logger.error(`Error during shutdown`, error);
        }
      } else if (i.customId === 'cancel_stop') {
        await i.update({
          embeds: [
            new EmbedBuilder()
              .setTitle('❌ Shutdown Cancelled')
              .setDescription('The authentication service shall continue running.')
              .setColor('#4CAF50')
              .setTimestamp()
          ],
          components: []
        });
      }
    });
  },
  
  'auth-all': async (interaction) => {
    if (!isStaffMember(interaction.member)) {
      return interaction.reply({
        content: 'Only Lords (staff members) can use this command! 📜',
        ephemeral: true
      });
    }
    
    const reason = interaction.options.getString('reason') || 'Mass verification of all members';
    
    const confirmButton = new ButtonBuilder()
      .setCustomId('confirm_auth_all')
      .setLabel('✅ Confirm Royal Seals For All')
      .setStyle(ButtonStyle.Danger);
    
    const cancelButton = new ButtonBuilder()
      .setCustomId('cancel_auth_all')
      .setLabel('❌ Cancel')
      .setStyle(ButtonStyle.Secondary);
    
    const actionRow = new ActionRowBuilder().addComponents(confirmButton, cancelButton);
    
    const confirmEmbed = new EmbedBuilder()
      .setTitle('⚠️ Grant Royal Seals To All?')
      .setDescription(`Art thou certain thou wishest to grant royal seals to ALL members without the verified role?\n\n**Reason:** ${reason}\n\nThis action shall grant all nobles immediate access to the realm.`)
      .setColor('#FF9B21')
      .setFooter({ text: 'This action affects all members without the verified role.' })
      .setTimestamp();
    
    const message = await interaction.reply({
      embeds: [confirmEmbed],
      components: [actionRow],
      ephemeral: true
    });
    
    const response = await message.fetch();
    
    const collector = response.createMessageComponentCollector({ 
      filter: i => i.user.id === interaction.user.id,
      time: 30000
    });
    
    collector.on('collect', async i => {
      if (i.customId === 'confirm_auth_all') {
        await i.update({
          embeds: [
            new EmbedBuilder()
              .setTitle('⏳ Granting Royal Seals...')
              .setDescription(`The authentication service is verifying all members without the royal seal. This may take some time.\n\n**Reason:** ${reason}`)
              .setColor('#FF9B21')
              .setTimestamp()
          ],
          components: []
        });
        
        try {
          const guild = client.guilds.cache.get(config.guildId);
          if (!guild) {
            return await i.editReply({
              embeds: [
                new EmbedBuilder()
                  .setTitle('❌ Error')
                  .setDescription('Could not find the guild.')
                  .setColor('#FF0000')
                  .setTimestamp()
              ]
            });
          }
          
          // Fetch all members - this might take time for large servers
          await guild.members.fetch();
          
          const membersWithoutRole = guild.members.cache.filter(member => 
            !member.user.bot && !member.roles.cache.has(config.verifiedRoleId)
          );
          
          if (membersWithoutRole.size === 0) {
            return await i.editReply({
              embeds: [
                new EmbedBuilder()
                  .setTitle('✅ No Action Needed')
                  .setDescription('All nobles in the realm already have their royal seals!')
                  .setColor('#4CAF50')
                  .setTimestamp()
              ]
            });
          }
          
          let successCount = 0;
          let failCount = 0;
          const startTime = Date.now();
          
          // Process members in batches to avoid rate limits
          for (const [memberId, member] of membersWithoutRole) {
            try {
              // Add role
              await member.roles.add(config.verifiedRoleId);
              
              
              // Update database
              if (!userDB.verifiedUsers[memberId]) {
                userDB.verifiedUsers[memberId] = {
                  id: memberId,
                  username: member.user.username,
                  discriminator: member.user.discriminator || '0',
                  globalName: member.user.globalName || member.user.username,
                  avatar: member.user.avatar,
                  verifiedAt: new Date().toISOString(),
                  verificationIP: 'mass-verification',
                  vassalage: 1,
                  tier: "knight",
                  manuallyVerifiedBy: interaction.user.id,
                  verificationReason: reason
                };
                
                // Update stats
                userDB.statistics.totalVerified++;
                const today = new Date().toISOString().split('T')[0];
                userDB.statistics.verificationsByDay[today] = 
                  (userDB.statistics.verificationsByDay[today] || 0) + 1;
              }
              
              // If user was deauthorized, remove from deauth list
              if (userDB.deauthorizedUsers && userDB.deauthorizedUsers[memberId]) {
                delete userDB.deauthorizedUsers[memberId];
              }
              
              successCount++;
              
              // Small delay to avoid rate limits
              if (successCount % 10 === 0) {
                await new Promise(resolve => setTimeout(resolve, 1000));
                
                // Provide updates for long-running operations
                if (successCount + failCount < membersWithoutRole.size) {
                  await i.editReply({
                    embeds: [
                      new EmbedBuilder()
                        .setTitle('⏳ Granting Royal Seals...')
                        .setDescription(`Progress: ${successCount + failCount}/${membersWithoutRole.size} nobles processed.`)
                        .setColor('#FF9B21')
                        .setTimestamp()
                    ]
                  }).catch(() => {});
                }
              }
            } catch (memberError) {
              logger.error(`Error granting role to ${memberId}`, memberError);
              failCount++;
            }
          }
          
          // Save database
          saveUserDB();
          
          // Log to the log channel
          const logChannel = guild.channels.cache.get(config.logChannelId);
          if (logChannel) {
            const logEmbed = new EmbedBuilder()
              .setTitle('📜 Royal Seal Status Update')
              .setDescription(`${successCount} members have been granted royal seals in a mass verification operation.`)
              .addFields([
                { name: 'Verification Details', value: `• ${successCount} nobles received verification\n• ${failCount} verification attempts failed\n• Database has been updated for all members`, inline: false },
                { name: 'Reason Provided', value: reason, inline: false },
                { name: 'Server Status', value: `Currently ${Object.keys(userDB.verifiedUsers).length} verified nobles in the realm`, inline: false },
                { name: 'Operation Info', value: `• Executed by: <@${interaction.user.id}>\n• Time taken: ${((Date.now() - startTime) / 1000).toFixed(2)} seconds\n• Timestamp: ${new Date().toLocaleString()}`, inline: false }
              ])
              .setColor(config.embedColor)
              .setFooter({ text: config.embedFooter })
              .setTimestamp();
            
            await logChannel.send({ embeds: [logEmbed] });
          }
          
          // Also log to the approval channel
          const approvalChannel = guild.channels.cache.get(config.approvalChannelId);
          if (approvalChannel) {
            const approvalEmbed = new EmbedBuilder()
              .setTitle('⚜️ Mass Verification Complete')
              .setDescription(`${successCount} nobles have been granted royal seals across the realm.`)
              .addFields([
                { name: 'Verification Summary', value: `• ${successCount} members verified successfully\n• ${failCount} verification attempts failed\n• All verified members now have the <@&${config.verifiedRoleId}> role\n• Verification database has been updated`, inline: false },
                { name: 'Reason Provided', value: reason, inline: false },
                { name: 'Server Impact', value: `The realm now has ${Object.keys(userDB.verifiedUsers).length} verified nobles with full access.`, inline: false },
                { name: 'Additional Information', value: `This action was authorized by <@${interaction.user.id}> at ${new Date().toLocaleString()}.`, inline: false }
              ])
              .setColor(config.embedColor)
              .setFooter({ text: 'This was a bulk operation - no DMs were sent' })
              .setTimestamp();
            
            await approvalChannel.send({ embeds: [approvalEmbed] });
          }
          
          // Final update to user
          await i.editReply({
            embeds: [
              new EmbedBuilder()
                .setTitle('✅ Royal Seals Granted')
                .setDescription(`Successfully granted royal seals to ${successCount} nobles!${failCount > 0 ? `\n\nFailed to process ${failCount} nobles.` : ''}`)
                .setColor('#4CAF50')
                .setTimestamp()
            ]
          });
          
        } catch (error) {
          logger.error(`Error during auth-all operation`, error);
          
          await i.editReply({
            embeds: [
              new EmbedBuilder()
                .setTitle('❌ Error')
                .setDescription(`There was an error while granting royal seals: ${error.message}`)
                .setColor('#FF0000')
                .setTimestamp()
            ]
          });
        }
      } else if (i.customId === 'cancel_auth_all') {
        await i.update({
          embeds: [
            new EmbedBuilder()
              .setTitle('❌ Operation Cancelled')
              .setDescription('The mass granting of royal seals hath been cancelled.')
              .setColor('#4CAF50')
              .setTimestamp()
          ],
          components: []
        });
      }
    });
  },
  
  'deauth-all': async (interaction) => {
    if (!isStaffMember(interaction.member)) {
      return interaction.reply({
        content: 'Only Lords (staff members) can use this command! 📜',
        ephemeral: true
      });
    }
    
    const confirmButton = new ButtonBuilder()
      .setCustomId('confirm_deauth_all')
      .setLabel('✅ Confirm Remove All Seals')
      .setStyle(ButtonStyle.Danger);
    
    const cancelButton = new ButtonBuilder()
      .setCustomId('cancel_deauth_all')
      .setLabel('❌ Cancel')
      .setStyle(ButtonStyle.Secondary);
    
    const actionRow = new ActionRowBuilder().addComponents(confirmButton, cancelButton);
    
    const confirmEmbed = new EmbedBuilder()
      .setTitle('⚠️ REMOVE ALL ROYAL SEALS?')
      .setDescription(`Art thou ABSOLUTELY CERTAIN thou wishest to REMOVE ALL royal seals from EVERY member?\n\n⚠️ **WARNING:** This is a DESTRUCTIVE ACTION that will REMOVE ACCESS from ALL verified members!\n\n⚠️ **WARNING:** This cannot be easily undone!`)
      .setColor('#FF0000')
      .setFooter({ text: 'This action affects ALL members with the verified role!' })
      .setTimestamp();
    
    const message = await interaction.reply({
      embeds: [confirmEmbed],
      components: [actionRow],
      ephemeral: true
    });
    
    const response = await message.fetch();
    
    const collector = response.createMessageComponentCollector({ 
      filter: i => i.user.id === interaction.user.id,
      time: 30000
    });
    
    collector.on('collect', async i => {
      if (i.customId === 'confirm_deauth_all') {
        await i.update({
          embeds: [
            new EmbedBuilder()
              .setTitle('⏳ Removing Royal Seals...')
              .setDescription(`The authentication service is removing all royal seals. This may take some time.`)
              .setColor('#FF0000')
              .setTimestamp()
          ],
          components: []
        });
        
        try {
          const guild = client.guilds.cache.get(config.guildId);
          if (!guild) {
            return await i.editReply({
              embeds: [
                new EmbedBuilder()
                  .setTitle('❌ Error')
                  .setDescription('Could not find the guild.')
                  .setColor('#FF0000')
                  .setTimestamp()
              ]
            });
          }
          
          // Fetch all members - this might take time for large servers
          await guild.members.fetch();
          
          const membersWithRole = guild.members.cache.filter(member => 
            !member.user.bot && member.roles.cache.has(config.verifiedRoleId)
          );
          
          if (membersWithRole.size === 0) {
            return await i.editReply({
              embeds: [
                new EmbedBuilder()
                  .setTitle('✅ No Action Needed')
                  .setDescription('No nobles in the realm have royal seals!')
                  .setColor('#4CAF50')
                  .setTimestamp()
              ]
            });
          }
          
          let successCount = 0;
          let failCount = 0;
          const startTime = Date.now();
          const reason = `Mass deauthorization by ${interaction.user.username} on ${new Date().toLocaleString()}`;
          
          // Process members in batches to avoid rate limits
          for (const [memberId, member] of membersWithRole) {
            try {
              // Remove role
              await member.roles.remove(config.verifiedRoleId);
              
              // Update database
              if (userDB.verifiedUsers[memberId]) {
                const userData = userDB.verifiedUsers[memberId];
                
                // Move to deauthorized list
                userDB.deauthorizedUsers[memberId] = {
                  ...userData,
                  deauthorizedAt: new Date().toISOString(),
                  deauthorizedBy: interaction.user.id,
                  deauthorizationReason: reason
                };
                
                // Remove from verified list
                delete userDB.verifiedUsers[memberId];
                
                // Update stats
                userDB.statistics.totalDeauths++;
              }
              
              successCount++;
              
              // Small delay to avoid rate limits
              if (successCount % 10 === 0) {
                await new Promise(resolve => setTimeout(resolve, 1000));
                
                // Provide updates for long-running operations
                if (successCount + failCount < membersWithRole.size) {
                  await i.editReply({
                    embeds: [
                      new EmbedBuilder()
                        .setTitle('⏳ Removing Royal Seals...')
                        .setDescription(`Progress: ${successCount + failCount}/${membersWithRole.size} nobles processed.`)
                        .setColor('#FF0000')
                        .setTimestamp()
                    ]
                  }).catch(() => {});
                }
              }
            } catch (memberError) {
              logger.error(`Error removing role from ${memberId}`, memberError);
              failCount++;
            }
          }
          
          // Save database
          saveUserDB();
          
          // Log to the log channel
          const logChannel = guild.channels.cache.get(config.logChannelId);
          if (logChannel) {
            const logEmbed = new EmbedBuilder()
              .setTitle('📜 Royal Seal Status Update')
              .setDescription(`${successCount} members have had their royal seals removed in a mass deauthorization operation.`)
              .addFields([
                { name: 'Deauthorization Details', value: `• ${successCount} nobles lost verification\n• ${failCount} deauthorization attempts failed\n• Database has been updated for all members`, inline: false },
                { name: 'Server Status', value: `Currently ${Object.keys(userDB.verifiedUsers).length} verified nobles remain in the realm`, inline: false },
                { name: 'Reason Provided', value: reason, inline: false },
                { name: 'Operation Info', value: `• Executed by: <@${interaction.user.id}>\n• Time taken: ${((Date.now() - startTime) / 1000).toFixed(2)} seconds\n• Timestamp: ${new Date().toLocaleString()}`, inline: false }
              ])
              .setColor('#FF0000')
              .setFooter({ text: config.embedFooter })
              .setTimestamp();
            
            await logChannel.send({ embeds: [logEmbed] });
          }
          
          // Also log to the approval channel
          const approvalChannel = guild.channels.cache.get(config.approvalChannelId);
          if (approvalChannel) {
            const approvalEmbed = new EmbedBuilder()
              .setTitle('⚜️ Mass Deauthorization Complete')
              .setDescription(`${successCount} nobles have had their royal seals revoked across the realm.`)
              .addFields([
                { name: 'Deauthorization Summary', value: `• ${successCount} members deauthorized successfully\n• ${failCount} deauthorization attempts failed\n• All affected members have lost the <@&${config.verifiedRoleId}> role\n• Verification database has been updated`, inline: false },
                { name: 'Server Impact', value: `The realm now has ${Object.keys(userDB.verifiedUsers).length} verified nobles with full access.`, inline: false },
                { name: 'Reason Provided', value: reason, inline: false },
                { name: 'Additional Information', value: `This action was authorized at ${new Date().toLocaleString()}.`, inline: false }
              ])
              .setColor('#FF0000')
              .setFooter({ text: 'This was a bulk operation - no DMs were sent' })
              .setTimestamp();
            
            await approvalChannel.send({ embeds: [approvalEmbed] });
          }
          
          // Final update to user
          await i.editReply({
            embeds: [
              new EmbedBuilder()
                .setTitle('✅ Royal Seals Removed')
                .setDescription(`Successfully removed royal seals from ${successCount} nobles!${failCount > 0 ? `\n\nFailed to process ${failCount} nobles.` : ''}`)
                .setColor('#4CAF50')
                .setTimestamp()
            ]
          });
          
        } catch (error) {
          logger.error(`Error during deauth-all operation`, error);
          
          await i.editReply({
            embeds: [
              new EmbedBuilder()
                .setTitle('❌ Error')
                .setDescription(`There was an error while removing royal seals: ${error.message}`)
                .setColor('#FF0000')
                .setTimestamp()
            ]
          });
        }
      } else if (i.customId === 'cancel_deauth_all') {
        await i.update({
          embeds: [
            new EmbedBuilder()
              .setTitle('❌ Operation Cancelled')
              .setDescription('The mass removal of royal seals hath been cancelled.')
              .setColor('#4CAF50')
              .setTimestamp()
          ],
          components: []
        });
      }
    });
  }
};

// Context menu handlers
const contextMenuHandlers = {
  // Verify Member context menu
  verifyMember: async (interaction) => {
    if (!isStaffMember(interaction.member)) {
      return interaction.reply({ 
        content: 'Only Lords (staff members) can use this command! 📜',
        ephemeral: true
      });
    }
    
    const user = interaction.targetUser;
    
    try {
      const member = await interaction.guild.members.fetch(user.id).catch(() => null);
      
      if (!member) {
        return interaction.reply({ 
          content: `❌ Noble <@${user.id}> is not in our realm.`,
          ephemeral: true
        });
      }
      
      if (userDB.verifiedUsers[user.id]) {
        return interaction.reply({ 
          content: `❌ Noble <@${user.id}> already hath a royal seal!`,
          ephemeral: true
        });
      }
      
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
        vassalage: 1,
        tier: "knight",
        manuallyVerifiedBy: interaction.user.id
      };
      
      userDB.verifiedUsers[user.id] = userData;
      
      userDB.statistics.totalVerified++;
      const today = new Date().toISOString().split('T')[0];
      userDB.statistics.verificationsByDay[today] = 
        (userDB.statistics.verificationsByDay[today] || 0) + 1;
      
      saveUserDB();
      
      await member.roles.add(config.verifiedRoleId);
      
      const logChannel = interaction.guild.channels.cache.get(config.logChannelId);
      if (logChannel) {
        const embed = new EmbedBuilder()
          .setTitle('📜 Noble Manually Added')
          .setDescription(`<@${user.id}> hath been manually given a royal seal by <@${interaction.user.id}>!`)
          .addFields([
            { name: 'Noble Name', value: `${user.username}#${user.discriminator}`, inline: true },
            { name: 'Noble ID', value: user.id, inline: true },
            { name: 'Added By', value: `<@${interaction.user.id}>`, inline: true }
          ])
          .setColor(config.embedColor)
          .setFooter({ text: config.embedFooter })
          .setTimestamp();
        
        await logChannel.send({ embeds: [embed] }).catch(() => {});
      }
      
      try {
        await member.send({
          embeds: [
            new EmbedBuilder()
              .setTitle('🎉 Welcome to the MonkeyBytes Realm!')
              .setDescription(config.welcomeMessage)
              .setColor(config.embedColor)
              .setFooter({ text: config.embedFooter })
          ]
        });
      } catch (dmError) {
        logger.warn(`Could not send welcome DM to ${user.username}`, dmError);
      }
      
      await interaction.reply({ 
        content: `✅ Successfully given a royal seal to <@${user.id}> and granted realm access!`,
        ephemeral: true
      });
    } catch (error) {
      logger.error(`Error during manual verification for ${user.id}`, error);
      await interaction.reply({
        content: `❌ Error giving royal seal: ${error.message}`,
        ephemeral: true
      });
    }
  },
  
  // Deauthorize Member context menu
  deauthorizeMember: async (interaction) => {
    if (!isStaffMember(interaction.member)) {
      return interaction.reply({ 
        content: 'Only Lords (staff members) can use this command! 📜',
        ephemeral: true
      });
    }
    
    const user = interaction.targetUser;
    
    const modal = new ModalBuilder()
      .setCustomId(`deauth_modal_${user.id}`)
      .setTitle(`Take ${user.username}'s Royal Seal`);

    const reasonInput = new TextInputBuilder()
      .setCustomId('deauth_reason')
      .setLabel('Reason for taking their royal seal')
      .setStyle(TextInputStyle.Paragraph)
      .setPlaceholder('Pray provide a reason for removing realm access')
      .setRequired(true)
      .setMaxLength(1000);

    const reasonRow = new ActionRowBuilder().addComponents(reasonInput);
    modal.addComponents(reasonRow);

    await interaction.showModal(modal);
  },
  
  // View User Stats context menu
  viewUserStats: async (interaction) => {
    if (!isStaffMember(interaction.member)) {
      return interaction.reply({ 
        content: 'Only Lords (staff members) can use this command! 📜',
        ephemeral: true
      });
    }
    
    const user = interaction.targetUser;
    
    try {
      const member = await interaction.guild.members.fetch(user.id).catch(() => null);
      
      if (!member) {
        return interaction.reply({
          content: `❌ Noble <@${user.id}> is not in our realm.`,
          ephemeral: true
        });
      }
      
      const isVerified = userDB.verifiedUsers && userDB.verifiedUsers[user.id];
      const isPending = userDB.pendingApprovals && userDB.pendingApprovals[user.id];
      const wasDeauthed = userDB.deauthorizedUsers && userDB.deauthorizedUsers[user.id];
      
      const joinDate = member.joinedAt ? new Date(member.joinedAt).toLocaleString() : 'Unknown';
      
      const verificationDate = isVerified && userDB.verifiedUsers[user.id].verifiedAt
        ? new Date(userDB.verifiedUsers[user.id].verifiedAt).toLocaleString()
        : 'N/A';
      
      const embed = new EmbedBuilder()
        .setTitle(`📊 Noble Stats: ${user.username}`)
        .setDescription(`Information about <@${user.id}> in our realm`)
        .addFields([
          { name: 'Noble ID', value: user.id, inline: true },
          { name: 'Joined Realm', value: joinDate, inline: true },
          { name: 'Royal Seal Status', value: isVerified 
            ? '✅ Has Royal Seal'
            : isPending 
                ? '⏳ Awaiting Royal Seal'
                : wasDeauthed 
                    ? '❌ Royal Seal Revoked'
                    : '❔ No Royal Seal',
            inline: true
          },
          { name: 'Royal Seal Given', value: verificationDate, inline: true },
          { name: 'Royal Markings', value: member.roles.cache.size > 1 
            ? member.roles.cache
                .filter(role => role.id !== interaction.guild.id)
                .map(role => `<@&${role.id}>`)
                .join(', ')
            : 'No markings',
            inline: false
          }
        ])
        .setColor(isVerified ? config.embedColor : wasDeauthed ? '#FF0000' : '#808080')
        .setFooter({ text: config.embedFooter })
        .setTimestamp();
      
      if (wasDeauthed) {
        embed.addFields([
          { name: 'Royal Seal Removal Reason', value: wasDeauthed.deauthorizationReason || 'No reason provided' },
          { name: 'Royal Seal Taken By', value: wasDeauthed.deauthorizedBy ? `<@${wasDeauthed.deauthorizedBy}>` : 'Unknown' },
          { name: 'Royal Seal Taken On', value: wasDeauthed.deauthorizedAt ? new Date(wasDeauthed.deauthorizedAt).toLocaleString() : 'Unknown' }
        ]);
      }
      
      await interaction.reply({
        embeds: [embed],
        ephemeral: true
      });
    } catch (error) {
      logger.error(`Error getting user stats`, error);
      await interaction.reply({
        content: `❌ Error retrieving noble stats: ${error.message}`,
        ephemeral: true
      });
    }
  },
  
  // Mark Rule Violation context menu
  markRuleViolation: async (interaction) => {
    if (!isStaffMember(interaction.member)) {
      return interaction.reply({ 
        content: 'Only Lords (staff members) can use this command! 📜',
        ephemeral: true
      });
    }
    
    const message = interaction.targetMessage;
    
    const modal = new ModalBuilder()
      .setCustomId(`violation_modal_${message.id}`)
      .setTitle('Mark as Royal Law Violation');
      
    const violationInput = new TextInputBuilder()
      .setCustomId('violation_type')
      .setLabel('Royal Law Violation Type')
      .setStyle(TextInputStyle.Short)
      .setPlaceholder('e.g. Treason, Insolence, Discourtesy')
      .setRequired(true);
      
    const notesInput = new TextInputBuilder()
      .setCustomId('violation_notes')
      .setLabel('Royal Notes')
      .setStyle(TextInputStyle.Paragraph)
      .setPlaceholder('Any additional notes about this violation')
      .setRequired(false);
      
    const violationRow = new ActionRowBuilder().addComponents(violationInput);
    const notesRow = new ActionRowBuilder().addComponents(notesInput);
    modal.addComponents(violationRow, notesRow);
    
    await interaction.showModal(modal);
  },
  
  // Add to Resources context menu 
  addToResources: async (interaction) => {
    if (!isStaffMember(interaction.member)) {
      return interaction.reply({ 
        content: 'Only Lords (staff members) can use this command! 📜',
        ephemeral: true
      });
    }
    
    const message = interaction.targetMessage;
    
    const modal = new ModalBuilder()
      .setCustomId(`resource_modal_${message.id}`)
      .setTitle('Add to Royal Knowledge');
      
    const categoryInput = new TextInputBuilder()
      .setCustomId('resource_category')
      .setLabel('Knowledge Category')
      .setStyle(TextInputStyle.Short)
      .setPlaceholder('e.g. Royal Coding, Quill Mastery, Parchment Works')
      .setRequired(true);
      
    const descriptionInput = new TextInputBuilder()
      .setCustomId('resource_description')
      .setLabel('Knowledge Description')
      .setStyle(TextInputStyle.Paragraph)
      .setPlaceholder('A brief description of this royal knowledge')
      .setRequired(true);
      
    const categoryRow = new ActionRowBuilder().addComponents(categoryInput);
    const descriptionRow = new ActionRowBuilder().addComponents(descriptionInput);
    modal.addComponents(categoryRow, descriptionRow);
    
    await interaction.showModal(modal);
  }
};

// ==================== MODAL SUBMISSION HANDLER ====================
async function handleModalSubmit(interaction) {
  // Handle deauth modal
  if (interaction.customId.startsWith('deauth_modal_')) {
    const userId = interaction.customId.split('_')[2];
    const reason = interaction.fields.getTextInputValue('deauth_reason');
    
    if (!reason || reason.trim() === '') {
      return interaction.reply({ 
        content: `❌ Thou must provide a reason for taking away this noble's royal seal.`,
        ephemeral: true
      });
    }
    
    await interaction.deferReply({ ephemeral: true });
    
    if (!userDB || !userDB.verifiedUsers || !userDB.verifiedUsers[userId]) {
      return interaction.editReply({ 
        content: `❌ Noble <@${userId}> doth not have a royal seal.`
      });
    }
    
    try {
      const member = await interaction.guild.members.fetch(userId).catch(() => null);
      const userData = { ...userDB.verifiedUsers[userId] };
      
      delete userDB.verifiedUsers[userId];
      
      userDB.deauthorizedUsers[userId] = {
        ...userData,
        deauthorizedAt: new Date().toISOString(),
        deauthorizedBy: interaction.user.id,
        deauthorizationReason: reason
      };
      
      userDB.statistics.totalDeauths++;
      
      saveUserDB();
      
      if (member) {
        if (member.roles.cache.has(config.verifiedRoleId)) {
          await member.roles.remove(config.verifiedRoleId).catch(err => {
            logger.error(`Error removing verified role from ${userId}`, err);
          });
        }
        
        try {
          const authUrl = `${config.serverUrl}/auth`;
          const embed = new EmbedBuilder()
            .setTitle('🛡️ MonkeyBytes Realm Access Update')
            .setDescription(`Thy royal seal hath been taken by a Lord, revoking thy access to the MonkeyBytes realm.\n\n**Reason:** ${reason}\n\nTo regain access to our coding kingdom, pray [click here to request a new royal seal](${authUrl}). After thou authenticateth, a Lord shall review thy request.`)
            .setColor('#FF9B21')
            .setFooter({ text: config.embedFooter })
            .setTimestamp();
          
          await member.send({ embeds: [embed] });
        } catch (dmError) {
          logger.warn(`Could not send deauth DM to user`, dmError);
        }
      }
      
      const logChannel = interaction.guild.channels.cache.get(config.logChannelId);
      if (logChannel) {
        const embed = new EmbedBuilder()
          .setTitle('📜 Royal Seal Confiscated')
          .setDescription(`<@${userId}>'s royal seal hath been taken by <@${interaction.user.id}>!`)
          .addFields(
            { name: 'Noble ID', value: userId, inline: true },
            { name: 'Action By', value: `<@${interaction.user.id}>`, inline: true },
            { name: 'Reason', value: reason, inline: false }
          )
          .setColor('#FF0000')
          .setFooter({ text: config.embedFooter })
          .setTimestamp();
        
        await logChannel.send({ embeds: [embed] }).catch(() => {});
      }
      
      await interaction.editReply({ 
        content: `✅ Successfully taken <@${userId}>'s royal seal with reason: "${reason}"`
      });
    } catch (error) {
      logger.error(`Error during deauthorization for ${userId}`, error);
      
      await interaction.editReply({ 
        content: `❌ Error taking royal seal: ${error.message}`
      });
    }
  }
  
  // Handle rule violation modal
  else if (interaction.customId.startsWith('violation_modal_')) {
    const messageId = interaction.customId.split('_')[2];
    const violationType = interaction.fields.getTextInputValue('violation_type');
    const notes = interaction.fields.getTextInputValue('violation_notes') || 'No additional notes provided';
    
    if (!violationType || violationType.trim() === '') {
      return interaction.reply({
        content: `❌ Thou must provide a violation type.`,
        ephemeral: true
      });
    }
    
    await interaction.deferReply({ ephemeral: true });
    
    try {
      const channel = interaction.channel;
      const message = await channel.messages.fetch(messageId).catch(() => null);
      
      if (!message) {
        return interaction.editReply({
          content: '❌ Error: Message not found. It may have been removed from the royal records.'
        });
      }
      
      const logChannel = interaction.guild.channels.cache.get(config.logChannelId);
      if (logChannel) {
        const embed = new EmbedBuilder()
          .setTitle('⚠️ Royal Law Violation')
          .setDescription(`A message hath been flagged as breaking royal laws by <@${interaction.user.id}>`)
          .addFields(
            { name: 'Noble', value: `<@${message.author.id}>`, inline: true },
            { name: 'Location', value: `<#${channel.id}>`, inline: true },
            { name: 'Violation Type', value: violationType, inline: true },
            { name: 'Notes', value: notes, inline: false },
            { name: 'Message Content', value: message.content || '(No text content - may contain attachments/embeds)', inline: false },
            { name: 'Message Link', value: `[Jump to Message](${message.url})`, inline: false }
          )
          .setColor('#FF0000')
          .setFooter({ text: config.embedFooter })
          .setTimestamp();
        
        await logChannel.send({ embeds: [embed] });
      }
      
      await interaction.editReply({
        content: `✅ Message marked as "${violationType}" royal law violation. Royal guards have been notified.`
      });
      
    } catch (error) {
      logger.error(`Error processing rule violation`, error);
      
      await interaction.editReply({
        content: `❌ Error processing royal violation: ${error.message}`
      });
    }
  }
  
  // Handle resource modal
  else if (interaction.customId.startsWith('resource_modal_')) {
    const messageId = interaction.customId.split('_')[2];
    const category = interaction.fields.getTextInputValue('resource_category');
    const description = interaction.fields.getTextInputValue('resource_description');
    
    if (!category || category.trim() === '' || !description || description.trim() === '') {
      return interaction.reply({
        content: `❌ Thou must provide both a category and description for royal knowledge.`,
        ephemeral: true
      });
    }
    
    await interaction.deferReply({ ephemeral: true });
    
    try {
      const channel = interaction.channel;
      const message = await channel.messages.fetch(messageId).catch(() => null);
      
      if (!message) {
        return interaction.editReply({
          content: '❌ Error: Message not found. It may have been removed from the royal records.'
        });
      }
      
      const resourcesChannel = interaction.guild.channels.cache.get(config.resourcesChannelId);
      if (!resourcesChannel) {
        return interaction.editReply({
          content: '❌ Royal archive not found. Please set up a knowledge storage chamber first.'
        });
      }
      
      const embed = new EmbedBuilder()
        .setTitle(`${category} Royal Resource`)
        .setDescription(description)
        .addFields(
          { name: 'Submitted By', value: `<@${message.author.id}>`, inline: true },
          { name: 'Added By', value: `<@${interaction.user.id}>`, inline: true },
          { name: 'Original Location', value: `[Jump to Original](${message.url})`, inline: false },
          { name: 'Resource Content', value: message.content || '(No text content - may contain attachments/embeds)' }
        )
        .setColor(config.embedColor)
        .setFooter({ text: config.embedFooter })
        .setTimestamp();
      
      const resourceMsg = await resourcesChannel.send({ embeds: [embed] });
      
      resourceEntries[resourceMsg.id] = {
        messageId: message.id,
        authorId: message.author.id,
        addedById: interaction.user.id,
        category,
        description,
        timestamp: new Date().toISOString()
      };
      
      const logChannel = interaction.guild.channels.cache.get(config.logChannelId);
      if (logChannel) {
        const logEmbed = new EmbedBuilder()
          .setTitle('📚 Royal Knowledge Added')
          .setDescription(`A new resource hath been added to the archives by <@${interaction.user.id}>`)
          .addFields(
            { name: 'Category', value: category, inline: true },
            { name: 'Added By', value: `<@${interaction.user.id}>`, inline: true },
            { name: 'Original Author', value: `<@${message.author.id}>`, inline: true },
            { name: 'Resource Link', value: `[Jump to Resource](${resourceMsg.url})`, inline: false }
          )
          .setColor(config.embedColor)
          .setFooter({ text: config.embedFooter })
          .setTimestamp();
        
        await logChannel.send({ embeds: [logEmbed] });
      }
      
      await interaction.editReply({
        content: `✅ Knowledge successfully added to the royal archives under category "${category}".`
      });
      
    } catch (error) {
      logger.error(`Error adding to resources`, error);
      
      await interaction.editReply({
        content: `❌ Error adding to royal knowledge: ${error.message}`
      });
    }
  }
}

// ==================== DOWNTIME TRACKING ====================
function ensureDowntimeDirectory() {
  try {
    const dbDir = path.dirname(downtimeFilePath);
    if (dbDir !== '.' && !fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }
    return true;
  } catch (error) {
    logger.error(`Failed to create downtime tracking directory`, error);
    return false;
  }
}

function loadDowntimeData() {
  try {
    ensureDowntimeDirectory();
    
    // Initialize with default data
    const defaultData = {
      lastOnline: new Date().toISOString(),
      startTime: new Date().toISOString(),
      downtimeEvents: [],
      totalDowntime: 0
    };
    
    if (fs.existsSync(downtimeFilePath)) {
      try {
        const data = fs.readFileSync(downtimeFilePath, 'utf8');
        if (!data || data.trim() === '') {
          fs.writeFileSync(downtimeFilePath, JSON.stringify(defaultData, null, 2));
          return defaultData;
        }
        
        const parsedData = JSON.parse(data);
        if (!parsedData.lastOnline || !parsedData.startTime || !parsedData.downtimeEvents) {
          fs.writeFileSync(downtimeFilePath, JSON.stringify(defaultData, null, 2));
          return defaultData;
        }
        
        return parsedData;
      } catch (parseError) {
        fs.writeFileSync(downtimeFilePath, JSON.stringify(defaultData, null, 2));
        return defaultData;
      }
    } else {
      fs.writeFileSync(downtimeFilePath, JSON.stringify(defaultData, null, 2));
      return defaultData;
    }
  } catch (error) {
    logger.error(`Error in loadDowntimeData: ${error.message}`, error);
    return {
      lastOnline: new Date().toISOString(),
      startTime: new Date().toISOString(),
      downtimeEvents: [],
      totalDowntime: 0
    };
  }
}

function saveDowntimeData(data) {
  try {
    ensureDowntimeDirectory();
    fs.writeFileSync(downtimeFilePath, JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    logger.error(`Error saving downtime data: ${error.message}`, error);
    return false;
  }
}

function updateLastOnlineTime() {
  try {
    const downtimeData = loadDowntimeData();
    downtimeData.lastOnline = new Date().toISOString();
    saveDowntimeData(downtimeData);
    return true;
  } catch (error) {
    logger.error(`Error updating last online time: ${error.message}`, error);
    return false;
  }
}

// Check for downtime that occurred while the bot was offline
function checkForDowntime() {
  try {
    const downtimeData = loadDowntimeData();
    
    let lastOnline;
    try {
      lastOnline = new Date(downtimeData.lastOnline);
      if (isNaN(lastOnline.getTime())) {
        throw new Error("Invalid date");
      }
    } catch (dateError) {
      logger.error(`Invalid last online date: ${dateError.message}`, dateError);
      lastOnline = new Date();
      downtimeData.lastOnline = lastOnline.toISOString();
      saveDowntimeData(downtimeData);
      return { detected: false };
    }
    
    const currentTime = new Date();
    const diffMilliseconds = Math.max(0, currentTime - lastOnline);
    const diffSeconds = Math.floor(diffMilliseconds / 1000);
    
    // If the difference is more than 2 minutes, count it as downtime
    if (diffSeconds > 120) {
      const downtimeMinutes = Math.floor(diffSeconds / 60);
      
      // Add the downtime event
      downtimeData.downtimeEvents.push({
        start: lastOnline.toISOString(),
        end: currentTime.toISOString(),
        duration: downtimeMinutes,
        detected: new Date().toISOString() // When it was detected
      });
      
      // Ensure totalDowntime is a number
      if (typeof downtimeData.totalDowntime !== 'number') {
        downtimeData.totalDowntime = 0;
      }
      
      // Update total downtime
      downtimeData.totalDowntime += downtimeMinutes;
      
      // Update last online time
      downtimeData.lastOnline = currentTime.toISOString();
      
      // Save the data
      saveDowntimeData(downtimeData);
      
      logger.warn(`Downtime of ${downtimeMinutes} minutes detected`);
      
      return {
        detected: true,
        duration: downtimeMinutes,
        start: lastOnline,
        end: currentTime
      };
    } else {
      // Update last online time
      downtimeData.lastOnline = currentTime.toISOString();
      saveDowntimeData(downtimeData);
      return { detected: false };
    }
  } catch (error) {
    logger.error(`Error checking for downtime: ${error.message}`, error);
    try {
      const downtimeData = loadDowntimeData();
      downtimeData.lastOnline = new Date().toISOString();
      saveDowntimeData(downtimeData);
    } catch (updateError) {
      logger.error(`Error updating last online time after downtime check error`, updateError);
    }
    return { detected: false, error: true };
  }
}

// Calculate uptime percentage based on recorded downtime
function calculateUptimePercentage() {
  try {
    const downtimeData = loadDowntimeData();
    
    let startTime;
    try {
      startTime = new Date(downtimeData.startTime);
      if (isNaN(startTime.getTime())) {
        throw new Error("Invalid date");
      }
    } catch (dateError) {
      logger.error(`Invalid start time: ${dateError.message}`, dateError);
      startTime = new Date();
      startTime.setDate(startTime.getDate() - 7); // Default to 7 days ago
      downtimeData.startTime = startTime.toISOString();
      saveDowntimeData(downtimeData);
    }
    
    const currentTime = new Date();
    const totalMinutes = Math.max(1, Math.floor((currentTime - startTime) / 1000 / 60));
    
    // Ensure totalDowntime is a number
    let totalDowntime = 0;
    if (typeof downtimeData.totalDowntime === 'number') {
      totalDowntime = downtimeData.totalDowntime;
    } else {
      logger.warn('totalDowntime is not a number, defaulting to 0');
      downtimeData.totalDowntime = 0;
      saveDowntimeData(downtimeData);
    }
    
    // Calculate uptime percentage
    const uptimePercentage = 100 - ((totalDowntime / totalMinutes) * 100);
    
    // Ensure the percentage is between 0 and 100
    return Math.max(0, Math.min(100, uptimePercentage)).toFixed(2);
  } catch (error) {
    logger.error(`Error calculating uptime percentage: ${error.message}`, error);
    return "99.99"; // Default to high uptime if calculation fails
  }
}

async function sendUptimeUpdate() {
  try {
    const uptime = Math.floor((new Date() - botStartTime) / 1000);
    const days = Math.floor(uptime / 86400);
    const hours = Math.floor((uptime % 86400) / 3600);
    const minutes = Math.floor((uptime % 3600) / 60);
    
    const uptimeString = `${days}d ${hours}h ${minutes}m`;
    const memoryUsage = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
    const uptimePercentage = calculateUptimePercentage();
    
    updateLastOnlineTime();
    
    const guild = client.guilds.cache.get(config.guildId);
    if (!guild) return;
    
    const uptimeLogsChannel = guild.channels.cache.get(config.uptimeLogsChannelId);
    if (!uptimeLogsChannel) return;
    
    const uptimeEmbed = new EmbedBuilder()
      .setTitle('🕒 Authentication Service Status')
      .addFields([
        { name: 'Service State', value: 'Online & Operational', inline: true },
        { name: 'Current Runtime', value: uptimeString, inline: true },
        { name: 'Memory Usage', value: `${memoryUsage} MB`, inline: true },
        { name: 'Discord Latency', value: `${client.ws.ping}ms`, inline: true },
        { name: 'Service Uptime', value: `${uptimePercentage}%`, inline: true }
      ])
      .setColor(config.embedColor)
      .setFooter({ text: config.embedFooter })
      .setTimestamp();
      
    await uptimeLogsChannel.send({ embeds: [uptimeEmbed] });
  } catch (error) {
    logger.error(`Failed to send uptime update`, error);
  }
}

async function sendHeartbeat() {
  try {
    const currentVerifiedCount = Object.keys(userDB.verifiedUsers || {}).length;
    const currentDeauthCount = Object.keys(userDB.deauthorizedUsers || {}).length;
    const pendingCount = Object.keys(userDB.pendingApprovals || {}).length;
    
    const heartbeatEmbed = new EmbedBuilder()
      .setTitle("🔐 OAuth Authentication Status")
      .setColor(config.embedColor)
      .addFields([
        {
          name: "Auth Service Status",
          value: `Online | ${client.user.tag}`,
          inline: true
        },
        {
          name: "Memory Usage",
          value: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`,
          inline: true
        },
        {
          name: "Verified Nobles",
          value: currentVerifiedCount.toString(),
          inline: true
        },
        {
          name: "Deauthorized Nobles",
          value: currentDeauthCount.toString(),
          inline: true
        },
        {
          name: "Pending Approvals",
          value: pendingCount.toString(),
          inline: true
        },
        {
          name: "Auth Statistics",
          value: `✅ ${userDB.statistics.totalVerified} nobles verified | ❌ ${userDB.statistics.totalDeauths} nobles deauthorized`,
          inline: false
        }
      ])
      .setFooter({ text: config.embedFooter })
      .setTimestamp();
    
    const guild = client.guilds.cache.get(config.guildId);
    if (guild) {
      const heartbeatChannel = guild.channels.cache.get(config.heartbeatChannelId);
      if (heartbeatChannel) {
        await heartbeatChannel.send({ embeds: [heartbeatEmbed] });
      }
    }
    
    updateLastOnlineTime();
  } catch (error) {
    logger.error(`Failed to send heartbeat`, error);
  }
}

// ==================== DISCORD BOT EVENTS ====================
client.once('ready', async () => {
  logger.startup(`Bot logged in as ${client.user.tag}`);
  
  // Check for signal files on startup
  try {
    if (fs.existsSync(RESTART_SIGNAL_FILE)) {
      fs.unlinkSync(RESTART_SIGNAL_FILE);
    }
    if (fs.existsSync(STOP_SIGNAL_FILE)) {
      fs.unlinkSync(STOP_SIGNAL_FILE);
    }
  } catch (error) {
    logger.error("Error checking signal files", error);
  }
  
  // Set bot presence
  setRotatingPresence();

  // Check for and update verification message ONLY during startup
  try {
    const guild = client.guilds.cache.get(config.guildId);
    if (guild) {
      const verificationChannel = guild.channels.cache.get(config.verificationChannelId);
      if (verificationChannel) {
        // Check if there's an existing verification message
        try {
          const messages = await verificationChannel.messages.fetch({ limit: 10 });
          const existingMessage = messages.find(msg => 
            msg.author.id === client.user.id && 
            msg.embeds.length > 0 && 
            msg.embeds[0].title.includes('Verification')
          );
          
          const verifyButton = new ButtonBuilder()
            .setCustomId('verify_button')
            .setLabel('📜 Receive Thy Royal Seal')
            .setStyle(ButtonStyle.Primary);

          const row = new ActionRowBuilder().addComponents(verifyButton);

          const embed = new EmbedBuilder()
            .setTitle('🛡️ MonkeyBytes Verification')
            .setDescription(config.verificationMessage)
            .setColor(config.embedColor)
            .setFooter({ text: config.embedFooter })
            .setTimestamp();
          
          if (existingMessage) {
            // Update existing message
            await existingMessage.edit({ embeds: [embed], components: [row] })
              .then(() => logger.success("Updated existing verification message during startup"))
              .catch(err => logger.error("Failed to update verification message", err));
          } else {
            // ONLY during startup/restart: create a new verification message if none exists
            logger.info("No verification message found during startup, creating a new one");
            await sendVerificationMessage(verificationChannel);
          }
        } catch (fetchError) {
          logger.warn("Error fetching messages during startup, creating a verification message", fetchError);
          await sendVerificationMessage(verificationChannel);
        }
      } else {
        logger.warn(`Verification channel not found! Please create a channel with ID: ${config.verificationChannelId}`);
      }
    }
  } catch (error) {
    logger.error("Error handling verification message during startup", error);
  }

  const guild = client.guilds.cache.get(config.guildId);
  if (guild) {
    await registerCommands(guild);
    
    // Check for downtime that occurred while the bot was offline
    const downtimeCheck = checkForDowntime();
    
    const uptimeLogsChannel = guild.channels.cache.get(config.uptimeLogsChannelId);
    if (uptimeLogsChannel) {
      const fields = [
        { name: 'Startup Time', value: new Date().toLocaleString(), inline: true },
        { name: 'Version', value: '1.3.0', inline: true },
        { name: 'Node Version', value: process.version, inline: true },
        { name: 'Memory', value: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`, inline: true },
        { name: 'Platform', value: process.platform, inline: true }
      ];
      
      if (downtimeCheck.detected) {
        fields.push(
          { name: 'Downtime Duration', value: `${downtimeCheck.duration} minutes`, inline: true },
          { name: 'Downtime Started', value: downtimeCheck.start.toLocaleString(), inline: true },
          { name: 'Service Resumed', value: new Date().toLocaleString(), inline: true }
        );
      }
      
      const uptimePercentage = calculateUptimePercentage();
      fields.push({ name: 'Overall Uptime', value: `${uptimePercentage}%`, inline: true });
      
      const uptimeEmbed = new EmbedBuilder()
        .setTitle(downtimeCheck.detected ? '🔄 Authentication Service Resumed' : '🟢 Authentication Service Started')
        .setDescription(downtimeCheck.detected 
          ? `MonkeyBytes Authentication Service is now back online after ${downtimeCheck.duration} minutes of downtime.`
          : `MonkeyBytes Authentication Service is now online and operational!`)
        .addFields(fields)
        .setColor(downtimeCheck.detected ? '#FFA500' : '#00FF00')
        .setFooter({ text: config.embedFooter })
        .setTimestamp();
        
      await uptimeLogsChannel.send({ embeds: [uptimeEmbed] });
    }
    
    // Run initial database sync on startup
    await syncDatabaseWithRoles();
    
    // Start heartbeats and checks
    sendHeartbeat();
    sendUptimeUpdate();
    setInterval(sendHeartbeat, config.heartbeatInterval);
    setInterval(sendUptimeUpdate, 300000); // Send uptime logs every 5 minutes
    setInterval(async () => {
      if (!userDB.pendingApprovals || Object.keys(userDB.pendingApprovals).length === 0) return;
      await checkPendingApprovals();
    }, 30000);
    
    // Run database sync every minute
    setInterval(syncDatabaseWithRoles, 60000);
    
    // Periodically update the "last online" time
    // This won't detect downtime while running (that's impossible),
    // but will help track when the bot was last alive for future startup checks
    setInterval(() => {
      updateLastOnlineTime();
    }, 300000); // Update every 5 minutes
  } else {
    logger.error(`Guild with ID ${config.guildId} not found`);
  }
});

client.on('interactionCreate', async interaction => {
  try {
    // Log command usage
    if (interaction.isChatInputCommand()) {
      // Slash command
      const { commandName, options } = interaction;
      const optionsString = options?._hoistedOptions?.map(opt => `${opt.name}:${opt.value}`).join(',') || '';
      
      logger.command(`Slash command executed: /${commandName} ${optionsString ? `[${optionsString}]` : ''} by ${interaction.user.username}#${interaction.user.discriminator} (${interaction.user.id})`);
    } else if (interaction.isUserContextMenuCommand() || interaction.isMessageContextMenuCommand()) {
      // Context menu command
      const { commandName, targetType } = interaction;
      const targetId = interaction.targetId;
      const targetString = targetType === 'USER' ? 
        `user: ${interaction.targetUser?.username}#${interaction.targetUser?.discriminator}` : 
        `message: ${targetId}`;
      
      logger.command(`Context menu "${commandName}" executed on ${targetString} by ${interaction.user.username}#${interaction.user.discriminator} (${interaction.user.id})`);
    }
    
    // Handle button interactions
    if (interaction.isButton()) {
      logger.command(`Button interaction: ${interaction.customId} clicked by ${interaction.user.username}#${interaction.user.discriminator} (${interaction.user.id})`);
      
      if (interaction.customId === 'verify_button') {
        if (userDB.verifiedUsers && userDB.verifiedUsers[interaction.user.id]) {
          return interaction.reply({
            content: '✅ Thou already hast thy royal seal! Thou art fully verified in the MonkeyBytes realm.',
            ephemeral: true
          });
        }
        
        return sendVerificationUrl(interaction);
      }
      
      // Let collector handle these specific buttons
      if (interaction.customId === 'confirm_restart' || 
          interaction.customId === 'cancel_restart' || 
          interaction.customId === 'confirm_stop' || 
          interaction.customId === 'cancel_stop' ||
          interaction.customId === 'confirm_auth_all' ||
          interaction.customId === 'cancel_auth_all' ||
          interaction.customId === 'confirm_deauth_all' ||
          interaction.customId === 'cancel_deauth_all') {
        // Don't process these here - the collector will handle them
        return;
      }
      
      // Handle approval/denial buttons
      if (interaction.customId.startsWith('approve_') || interaction.customId.startsWith('deny_')) {
        if (!isStaffMember(interaction.member)) {
          return interaction.reply({ 
            content: 'Only Lords (staff members) can use this command! 📜',
            ephemeral: true
          });
        }
        
        const approved = interaction.customId.startsWith('approve_');
        const userId = interaction.customId.split('_')[1];
        
        await interaction.deferReply({ ephemeral: true });
        
        const success = await processVerificationApproval(userId, approved, interaction.user.id);
        
        if (success) {
          try {
            await interaction.message.react(approved ? '✅' : '❌');
          } catch (reactError) {
            logger.warn(`Error adding reaction to message`, reactError);
          }
          
          await interaction.editReply({
            content: `✅ Successfully ${approved ? 'granted a royal seal to' : 'denied realm access for'} <@${userId}>.`,
          });
          
          const updatedEmbed = EmbedBuilder.from(interaction.message.embeds[0])
            .setTitle(approved ? '✅ Royal Seal Granted' : '❌ Royal Seal Denied')
            .setDescription(`<@${userId}>'s royal seal request hath been ${approved ? 'approved' : 'denied'} by <@${interaction.user.id}>.`)
            .setColor(approved ? config.embedColor : '#FF0000')
            .setTimestamp();
          
          await interaction.message.edit({ 
            embeds: [updatedEmbed],
            components: []
          }).catch(() => {});
        } else {
          await interaction.editReply({
            content: `❌ Error processing ${approved ? 'approval' : 'denial'}. Noble might no longer be waiting.`,
          });
        }
        
        return;
      }
    }
    
    // Handle slash commands
    if (interaction.isChatInputCommand()) {
      const { commandName } = interaction;
      
      // Check if command exists in our handlers
      if (commandHandlers[commandName]) {
        await commandHandlers[commandName](interaction);
      } else if (commandName === 'verify') {
        if (userDB.verifiedUsers && userDB.verifiedUsers[interaction.user.id]) {
          return interaction.reply({
            content: '✅ Thou already hast thy royal seal! Thou art fully verified in the MonkeyBytes realm.',
            ephemeral: true
          });
        }
        return sendVerificationUrl(interaction);
      }
    }
    
    // Handle context menu commands
    if (interaction.isUserContextMenuCommand()) {
      switch(interaction.commandName) {
        case 'Verify Member':
          await contextMenuHandlers.verifyMember(interaction);
          break;
        case 'Deauthorize Member':
          await contextMenuHandlers.deauthorizeMember(interaction);
          break;
        case 'View User Stats':
          await contextMenuHandlers.viewUserStats(interaction);
          break;
      }
    }
    
    if (interaction.isMessageContextMenuCommand()) {
      switch(interaction.commandName) {
        case 'Mark as Rule Violation':
          await contextMenuHandlers.markRuleViolation(interaction);
          break;
        case 'Add to Resources':
          await contextMenuHandlers.addToResources(interaction);
          break;
      }
    }
    
    // Handle modal submissions
    if (interaction.isModalSubmit()) {
      logger.command(`Modal submitted: ${interaction.customId} by ${interaction.user.username}#${interaction.user.discriminator} (${interaction.user.id})`);
      await handleModalSubmit(interaction);
    }
  } catch (error) {
    logger.error(`Error in interaction handler`, error);
    
    try {
      if (interaction.replied || interaction.deferred) {
        await interaction.editReply({
          content: `❌ There was a glitch in the realm. Pray try again later.`,
          ephemeral: true
        }).catch(() => {});
      } else {
        await interaction.reply({
          content: `❌ There was a glitch in the realm. Pray try again later.`,
          ephemeral: true
        }).catch(() => {});
      }
    } catch (replyError) {
      logger.error(`Failed to send error response`, replyError);
    }
  }
});

// Handle members leaving the server
client.on('guildMemberRemove', async member => {
  try {
    const userId = member.id;
    
    // Check if the user was verified
    if (userDB.verifiedUsers && userDB.verifiedUsers[userId]) {
      logger.info(`Verified user left server: ${member.user.username}#${member.user.discriminator} (${userId})`);
      
      const userData = { ...userDB.verifiedUsers[userId] };
      
      // Remove from verified list
      delete userDB.verifiedUsers[userId];
      
      // Add to deauthorized list with reason
      userDB.deauthorizedUsers[userId] = {
        ...userData,
        deauthorizedAt: new Date().toISOString(),
        deauthorizedBy: 'system',
        deauthorizationReason: 'User left the server'
      };
      
      // Update statistics
      userDB.statistics.totalDeauths++;
      
      // Save the database
      saveUserDB();
      
      // Log to the log channel if available
      const guild = client.guilds.cache.get(config.guildId);
      if (guild) {
        const logChannel = guild.channels.cache.get(config.logChannelId);
        if (logChannel) {
          const embed = new EmbedBuilder()
            .setTitle('👋 Noble Left the Realm')
            .setDescription(`<@${userId}> (${member.user.username}#${member.user.discriminator}) hath departed from our realm.`)
            .addFields([
              { name: 'Noble ID', value: userId, inline: true },
              { name: 'Verification Status', value: 'Royal Seal Revoked Due to Departure', inline: true }
            ])
            .setColor('#FF9B21')
            .setFooter({ text: config.embedFooter })
            .setTimestamp();
          
          await logChannel.send({ embeds: [embed] }).catch(() => {});
        }
      }
    }
  } catch (error) {
    logger.error(`Error handling member leave for ${member.id}`, error);
  }
});

// ==================== SHUTDOWN HANDLING ====================
async function shutdown() {
  try {
    updateLastOnlineTime();
    saveUserDB();
    
    try {
      const guild = client.guilds.cache.get(config.guildId);
      if (guild) {
        const uptimeLogsChannel = guild.channels.cache.get(config.uptimeLogsChannelId);
        if (uptimeLogsChannel) {
          const embed = new EmbedBuilder()
            .setTitle('🛑 Authentication Service Shutting Down')
            .setDescription('MonkeyBytes Authentication Service is shutting down now.')
            .setColor('#FF0000')
            .setTimestamp();
          
          await uptimeLogsChannel.send({ embeds: [embed] });
        }
      }
    } catch (discordError) {
      logger.error('Failed to send shutdown message to Discord', discordError);
    }
    
    try {
      fs.writeFileSync(STOP_SIGNAL_FILE, `System-initiated shutdown at ${new Date().toISOString()}`);
    } catch (fileError) {
      logger.error('Failed to create stop signal file during shutdown', fileError);
    }
    
    await client.destroy();
    
    if (server) {
      server.close();
    }
    
    setTimeout(() => process.exit(0), 1500);
  } catch (error) {
    logger.error('Error during shutdown', error);
    setTimeout(() => process.exit(1), 1500);
  }
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// ==================== ERROR HANDLING ====================
process.on('uncaughtException', (error) => {
  logger.error(`Uncaught Exception: ${error.message}`, error);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error(`Unhandled Rejection at: ${promise}, reason: ${reason}`, reason);
});

// ==================== INITIALIZATION ====================
logger.startup('📜 Starting MonkeyBytes Royal Bot');
ensureDatabaseDirectory();
ensureUserDBStructure();
loadUserDB();

// Start Express server
let server;
try {
  server = app.listen(config.port, () => {
    logger.startup(`Express server running on port ${config.port}`);
  });
  
  server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
      logger.error(`Port ${config.port} is already in use.`);
      process.exit(1);
    } else {
      logger.error(`Express server error: ${error.message}`, error);
    }
  });
} catch (serverError) {
  logger.error(`Failed to start Express server: ${serverError.message}`, serverError);
  process.exit(1);
}

// Login to Discord
client.login(config.token).catch(error => {
  logger.error('Failed to log in to Discord', error);
  setTimeout(() => {
    logger.startup('Attempting to reconnect...');
    client.login(config.token).catch(reconnectError => {
      logger.error('Reconnection attempt failed', reconnectError);
    });
  }, 30000);
});