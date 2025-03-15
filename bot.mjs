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
  clientId: 'YOUR_CLIENT_ID_HERE',
  clientSecret: 'YOUR_CLIENT_SECRET_HERE',
  token: 'YOUR_BOT_TOKEN_HERE',
  port: 20295,
  redirectUri: 'http://your-domain.com:20295/auth/callback',
  serverUrl: 'http://your-domain.com:20295',
  guildId: 'YOUR_GUILD_ID_HERE',
  verifiedRoleId: 'YOUR_VERIFIED_ROLE_ID_HERE', 
  staffRoleId: 'YOUR_STAFF_ROLE_ID_HERE', 
  verificationCategoryId: 'YOUR_VERIFICATION_CATEGORY_ID_HERE',
  verificationChannelId: 'YOUR_VERIFICATION_CHANNEL_ID_HERE',
  logChannelId: 'YOUR_LOG_CHANNEL_ID_HERE',
  approvalChannelId: 'YOUR_APPROVAL_CHANNEL_ID_HERE',
  heartbeatChannelId: 'YOUR_HEARTBEAT_CHANNEL_ID_HERE',
  uptimeLogsChannelId: 'YOUR_UPTIME_LOGS_CHANNEL_ID_HERE',
  resourcesChannelId: 'YOUR_RESOURCES_CHANNEL_ID_HERE',
  sessionSecret: 'YOUR_SESSION_SECRET_HERE',
  dbPath: './monkey-verified-users.json',
  embedColor: '#3eff06',
  embedFooter: '© MonkeyBytes Tech | The Code Jungle',
  welcomeMessage: "🎉 You got your banana! Welcome to the MonkeyBytes jungle! 🌴\n\nYour verification has been approved by our monkey elders, and you now have full access to all our coding vines, jungle channels, and community treehouse.\n\n🐒 Don't be shy - introduce yourself to the other monkeys in our community channels\n💻 Explore our code repositories and learning resources in the banana archives\n🍌 Enjoy your verified status and all the jungle perks that come with it!\n\nIf you need help swinging through the vines, our monkey guides are just a message away!",
  verificationMessage: "To join the MonkeyBytes jungle, you'll need to get your verification banana. Click the button below to begin the verification process! 🍌\n\nAfter you authenticate, a monkey elder will review and approve your request.\n\nThis verification process helps us keep our coding jungle safe from curious snakes and mischievous critters.",
  heartbeatInterval: 630000, // 10.5 minutes
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
    console.log(`[${level}] ${message}`);
    if (error) console.error(error);
    return true;
  },
  info: (msg, err) => logger.log(msg, 'INFO', err),
  warn: (msg, err) => logger.log(msg, 'WARN', err),
  error: (msg, err) => logger.log(msg, 'ERROR', err),
  success: (msg, err) => logger.log(msg, 'SUCCESS', err),
  startup: (msg, err) => logger.log(msg, 'STARTUP', err)
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
    <h1>MonkeyBytes Jungle Authentication</h1>
    <p>Click the button below to get your banana and access the coding jungle!</p>
    <a href="/auth" class="button">Get Your Banana 🍌</a>
  `, 'MonkeyBytes Jungle Authentication', '#FF9B21'),
  
  pendingPage: () => htmlTemplates.wrapper(`
    <div class="icon">⏳</div>
    <h1>Awaiting Banana Approval</h1>
    <p>Your request to join the MonkeyBytes jungle has been sent to the monkey elders for approval.</p>
    <p>You will be notified once they've reviewed your request!</p>
    <p>You can close this window and return to Discord.</p>
  `, 'Awaiting Banana Approval', '#FFA500'),
  
  successPage: () => htmlTemplates.wrapper(`
    <div class="icon">✓</div>
    <h1>You Got Your Banana!</h1>
    <p>You have been verified and can now access the MonkeyBytes jungle!</p>
    <p>You can close this window and return to Discord.</p>
  `, 'Verification Successful', '#4CAF50'),
  
  errorPage: () => htmlTemplates.wrapper(`
    <div class="icon">❌</div>
    <h1>Jungle Authentication Error</h1>
    <p>Oh no! The banana slipped. An error occurred during the verification process.</p>
    <p>If this problem persists, please contact a monkey elder (server administrator).</p>
  `, 'Jungle Authentication Error', '#FF5555'),
  
  serverErrorPage: () => htmlTemplates.wrapper(`
    <div class="icon">❌</div>
    <h1>Jungle Server Error</h1>
    <p>The monkeys are having technical difficulties. Please try again later!</p>
  `, 'Jungle Server Error', '#FF5555')
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
    bananaCount: 1,
    tier: "banana"
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
    { text: '🍌 Type /help for jungle guidance', type: ActivityType.Playing },
    { text: '👆 Click for a banana in #get-your-banana', type: ActivityType.Watching },
    { text: '🔑 Get verified for full jungle access', type: ActivityType.Competing },
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
      .setLabel('✅ Accept')
      .setStyle(ButtonStyle.Success);
    
    const denyButton = new ButtonBuilder()
      .setCustomId(`deny_${userId}`)
      .setLabel('❌ Deny')
      .setStyle(ButtonStyle.Danger);
    
    const actionRow = new ActionRowBuilder()
      .addComponents(acceptButton, denyButton);
    
    const embed = new EmbedBuilder()
      .setTitle('🍌 Pending Banana Request')
      .setDescription(`<@${userId}> (${username}) is requesting to join the jungle.${
        wasDeauthorized 
          ? `\n\n⚠️ **Note:** This monkey previously had their banana taken.\n**Reason:** ${wasDeauthorized.deauthorizationReason || 'No reason provided'}` 
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
                .setTitle('🍌 New Monkey in the Jungle')
                .setDescription(`<@${userId}> has been given their banana after jungle elder approval!`)
                .addFields(
                  { name: 'Monkey Name', value: `${userData.username}#${userData.discriminator}`, inline: true },
                  { name: 'Monkey ID', value: userId, inline: true },
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
                    .setTitle('🎉 Welcome to the MonkeyBytes Jungle!')
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
            .setTitle('❌ Banana Request Denied')
            .setDescription(`<@${userId}>'s request to join the jungle was denied by <@${staffId}>.`)
            .addFields(
              { name: 'Monkey Name', value: `${userData.username}#${userData.discriminator}`, inline: true },
              { name: 'Monkey ID', value: userId, inline: true },
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
                  .setTitle('❌ Banana Access Denied')
                  .setDescription(`Your request to join the MonkeyBytes jungle has been declined by our monkey elders. If you believe this is a mistake in the jungle, please contact the server administrators to appeal.`)
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
    .setLabel('🍌 Get Your Banana')
    .setStyle(ButtonStyle.Primary);

  const row = new ActionRowBuilder().addComponents(verifyButton);

  const embed = new EmbedBuilder()
    .setTitle('🐵 MonkeyBytes Verification')
    .setDescription(config.verificationMessage)
    .setColor(config.embedColor)
    .setFooter({ text: config.embedFooter })
    .setTimestamp();

  await channel.send({ embeds: [embed], components: [row] });
}

function sendVerificationUrl(interaction) {
  const authUrl = `${config.serverUrl}/auth`;
  const embed = new EmbedBuilder()
    .setTitle('🐵 Get Your Banana!')
    .setDescription(`Click [here to verify](${authUrl}) your account and join the jungle.\n\nThis will open the authentication page. After authorizing with Discord, the monkey elders will review your request.`)
    .setColor(config.embedColor)
    .setFooter({ text: config.embedFooter })
    .setTimestamp();

  return interaction.reply({ embeds: [embed], ephemeral: true });
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
      .setTitle('🐵 MonkeyBytes Jungle Guide')
      .setDescription('Welcome to the coding jungle! Here are some banana-powered commands to help you navigate:')
      .addFields(
        { name: '/help', value: 'Shows this jungle guide', inline: true },
        { name: '/verify', value: 'Get your banana (verification access)', inline: true },
        { name: '/resources', value: 'Discover coding treasures', inline: true },
        { name: '/roles', value: 'Learn about jungle tribes (roles)', inline: true },
        { name: '/report', value: 'Alert monkey guards about issues', inline: true }
      )
      .setColor(config.embedColor)
      .setFooter({ text: config.embedFooter })
      .setTimestamp();

    return interaction.reply({ embeds: [embed], ephemeral: true });
  },
  
  resources: async (interaction) => {
    const embed = new EmbedBuilder()
      .setTitle('🍌 Code Jungle Treasures')
      .setDescription('Explore these valuable coding resources in our monkey community:')
      .addFields(
        { name: '📚 Learning Vines', value: 'Swing by #beginner-help, #code-discussion, and #project-showcase to learn and share your work.' },
        { name: '🛠️ Monkey Tools', value: 'Our jungle has dedicated zones for popular frameworks and tools. Explore the channel list to find your coding habitat.' },
        { name: '📝 Banana Archives', value: 'Check the pinned messages in each channel for valuable code snippets and preserved knowledge!' },
        { name: '🔗 Outside World Links', value: 'Visit our website for specially curated tutorials and documentation links for monkey coders of all levels.' }
      )
      .setColor(config.embedColor)
      .setFooter({ text: config.embedFooter })
      .setTimestamp();

    return interaction.reply({ embeds: [embed], ephemeral: true });
  },
  
  roles: async (interaction) => {
    const embed = new EmbedBuilder()
      .setTitle('🍌 Jungle Tribe Roles')
      .setDescription('Discover the different tribes you can join in our coding jungle:')
      .addFields(
        { name: '🔑 Verified Monkey', value: 'Basic jungle access. Obtained by getting your banana (verification).' },
        { name: '💻 Language Tribes', value: 'Visit the #role-selection tree to choose your programming language tribes.' },
        { name: '🏆 Experience Levels', value: 'Show your jungle experience level in the #role-selection area.' },
        { name: '⭐ Community Guide', value: 'Awarded to active monkeys who help others find their way through the code jungle.' },
        { name: '🍌 Banana Master', value: 'Elite status for exceptionally helpful jungle members. Nominated by the monkey elders.' }
      )
      .setColor(config.embedColor)
      .setFooter({ text: config.embedFooter })
      .setTimestamp();

    return interaction.reply({ embeds: [embed], ephemeral: true });
  },
  
  report: async (interaction) => {
    const issue = interaction.options.getString('issue');
    const user = interaction.user;
    
    const reportEmbed = new EmbedBuilder()
      .setTitle('🚨 Jungle Incident Report')
      .setDescription(`A report has been submitted by <@${user.id}>`)
      .addFields(
        { name: 'Reporting Monkey', value: `${user.username}#${user.discriminator || '0'}`, inline: true },
        { name: 'Monkey ID', value: user.id, inline: true },
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
          content: 'Your alert has been sent to the monkey guards. Thank you for helping keep our code jungle safe! 🐵', 
          ephemeral: true 
        });
      } else {
        throw new Error('Log channel not found');
      }
    } catch (error) {
      logger.error(`Error processing report`, error);
      await interaction.reply({ 
        content: 'There was a glitch in the jungle. Please contact a monkey elder directly.', 
        ephemeral: true 
      });
    }
  },
  
  restart: async (interaction) => {
    if (!isStaffMember(interaction.member)) {
      return interaction.reply({
        content: 'Only monkey elders (staff members) can use this command! 🍌',
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
      .setTitle('⚠️ Monkey Nap Time?')
      .setDescription(`Are you sure you want to send the monkey bot for a quick nap?\n\n**Reason:** ${reason}`)
      .setColor('#FF9B21')
      .setFooter({ text: 'This action will briefly disconnect the monkey bot.' })
      .setTimestamp();
    
    const message = await interaction.reply({
      embeds: [confirmEmbed],
      components: [actionRow],
      ephemeral: true,
    });
    
    const collector = message.createMessageComponentCollector({ 
      filter: i => i.user.id === interaction.user.id,
      time: 30000
    });
    
    collector.on('collect', async i => {
      if (i.customId === 'confirm_restart') {
        await i.update({
          embeds: [
            new EmbedBuilder()
              .setTitle('🔄 Monkey Nap Initiated')
              .setDescription(`Monkey bot is going for a quick nap, requested by <@${interaction.user.id}>.\n\n**Reason:** ${reason}\n\nThe monkey will wake up and be back online shortly.`)
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
              .setTitle('🔄 Monkey Nap Initiated')
              .setDescription(`Bot restart has been initiated by <@${interaction.user.id}>.`)
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
              .setTitle('❌ Monkey Nap Cancelled')
              .setDescription('The bot will continue swinging through the vines.')
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
        content: 'Only monkey elders (staff members) can use this command! 🍌',
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
      .setTitle('⚠️ Monkey Hibernation?')
      .setDescription(`Are you sure you want to send the monkey to sleep?\n\n**Reason:** ${reason}\n\n**⚠️ WARNING:** This will completely shut down the monkey bot until manually awakened.`)
      .setColor('#FF0000')
      .setFooter({ text: 'This action will disconnect the monkey until manually restarted.' })
      .setTimestamp();
    
    const message = await interaction.reply({
      embeds: [confirmEmbed],
      components: [actionRow],
      ephemeral: true,
    });
    
    const collector = message.createMessageComponentCollector({ 
      filter: i => i.user.id === interaction.user.id,
      time: 30000
    });
    
    collector.on('collect', async i => {
      if (i.customId === 'confirm_stop') {
        await i.update({
          embeds: [
            new EmbedBuilder()
              .setTitle('🛑 Monkey Hibernation Initiated')
              .setDescription(`Monkey bot is going into hibernation, requested by <@${interaction.user.id}>.\n\n**Reason:** ${reason}\n\nThe monkey will need to be manually awakened.`)
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
              .setTitle('🛑 Monkey Hibernation Initiated')
              .setDescription(`Bot shutdown has been initiated by <@${interaction.user.id}>.`)
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
              .setTitle('❌ Hibernation Cancelled')
              .setDescription('The monkey will stay awake and continue to swing through the vines.')
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
        content: 'Only monkey elders (staff members) can use this command! 🍌',
        ephemeral: true
      });
    }
    
    const user = interaction.targetUser;
    
    try {
      const member = await interaction.guild.members.fetch(user.id).catch(() => null);
      
      if (!member) {
        return interaction.reply({ 
          content: `❌ Monkey <@${user.id}> is not in our jungle.`,
          ephemeral: true
        });
      }
      
      if (userDB.verifiedUsers[user.id]) {
        return interaction.reply({ 
          content: `❌ Monkey <@${user.id}> already has a banana!`,
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
        bananaCount: 1,
        tier: "banana",
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
          .setTitle('🍌 Monkey Manually Added')
          .setDescription(`<@${user.id}> has been manually given a banana by <@${interaction.user.id}>!`)
          .addFields([
            { name: 'Monkey Name', value: `${user.username}#${user.discriminator}`, inline: true },
            { name: 'Monkey ID', value: user.id, inline: true },
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
              .setTitle('🎉 Welcome to the MonkeyBytes Jungle!')
              .setDescription(config.welcomeMessage)
              .setColor(config.embedColor)
              .setFooter({ text: config.embedFooter })
          ]
        });
      } catch (dmError) {
        logger.warn(`Could not send welcome DM to ${user.username}`, dmError);
      }
      
      await interaction.reply({ 
        content: `✅ Successfully given a banana to <@${user.id}> and granted jungle access!`,
        ephemeral: true
      });
    } catch (error) {
      logger.error(`Error during manual verification for ${user.id}`, error);
      await interaction.reply({
        content: `❌ Error giving banana: ${error.message}`,
        ephemeral: true
      });
    }
  },
  
  // Deauthorize Member context menu
  deauthorizeMember: async (interaction) => {
    if (!isStaffMember(interaction.member)) {
      return interaction.reply({ 
        content: 'Only monkey elders (staff members) can use this command! 🍌',
        ephemeral: true
      });
    }
    
    const user = interaction.targetUser;
    
    const modal = new ModalBuilder()
      .setCustomId(`deauth_modal_${user.id}`)
      .setTitle(`Take ${user.username}'s Banana`);

    const reasonInput = new TextInputBuilder()
      .setCustomId('deauth_reason')
      .setLabel('Reason for taking their banana')
      .setStyle(TextInputStyle.Paragraph)
      .setPlaceholder('Please provide a reason for removing jungle access')
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
        content: 'Only monkey elders (staff members) can use this command! 🍌',
        ephemeral: true
      });
    }
    
    const user = interaction.targetUser;
    
    try {
      const member = await interaction.guild.members.fetch(user.id).catch(() => null);
      
      if (!member) {
        return interaction.reply({
          content: `❌ Monkey <@${user.id}> is not in our jungle.`,
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
        .setTitle(`📊 Monkey Stats: ${user.username}`)
        .setDescription(`Information about <@${user.id}> in our jungle`)
        .addFields([
          { name: 'Monkey ID', value: user.id, inline: true },
          { name: 'Joined Jungle', value: joinDate, inline: true },
          { name: 'Banana Status', value: isVerified 
            ? '✅ Has Banana'
            : isPending 
                ? '⏳ Awaiting Banana'
                : wasDeauthed 
                    ? '❌ Banana Taken'
                    : '❔ No Banana',
            inline: true
          },
          { name: 'Banana Given', value: verificationDate, inline: true },
          { name: 'Jungle Markings', value: member.roles.cache.size > 1 
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
          { name: 'Banana Removal Reason', value: wasDeauthed.deauthorizationReason || 'No reason provided' },
          { name: 'Banana Taken By', value: wasDeauthed.deauthorizedBy ? `<@${wasDeauthed.deauthorizedBy}>` : 'Unknown' },
          { name: 'Banana Taken On', value: wasDeauthed.deauthorizedAt ? new Date(wasDeauthed.deauthorizedAt).toLocaleString() : 'Unknown' }
        ]);
      }
      
      await interaction.reply({
        embeds: [embed],
        ephemeral: true
      });
    } catch (error) {
      logger.error(`Error getting user stats`, error);
      await interaction.reply({
        content: `❌ Error retrieving monkey stats: ${error.message}`,
        ephemeral: true
      });
    }
  },
  
  // Mark Rule Violation context menu
  markRuleViolation: async (interaction) => {
    if (!isStaffMember(interaction.member)) {
      return interaction.reply({ 
        content: 'Only monkey elders (staff members) can use this command! 🍌',
        ephemeral: true
      });
    }
    
    const message = interaction.targetMessage;
    
    const modal = new ModalBuilder()
      .setCustomId(`violation_modal_${message.id}`)
      .setTitle('Mark as Jungle Rule Violation');
      
    const violationInput = new TextInputBuilder()
      .setCustomId('violation_type')
      .setLabel('Jungle Rule Violation Type')
      .setStyle(TextInputStyle.Short)
      .setPlaceholder('e.g. Monkey Business, Snake Talk, Loud Howling')
      .setRequired(true);
      
    const notesInput = new TextInputBuilder()
      .setCustomId('violation_notes')
      .setLabel('Jungle Notes')
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
        content: 'Only monkey elders (staff members) can use this command! 🍌',
        ephemeral: true
      });
    }
    
    const message = interaction.targetMessage;
    
    const modal = new ModalBuilder()
      .setCustomId(`resource_modal_${message.id}`)
      .setTitle('Add to Jungle Knowledge');
      
    const categoryInput = new TextInputBuilder()
      .setCustomId('resource_category')
      .setLabel('Knowledge Category')
      .setStyle(TextInputStyle.Short)
      .setPlaceholder('e.g. Banana Coding, Vine Swinging, Tree Climbing')
      .setRequired(true);
      
    const descriptionInput = new TextInputBuilder()
      .setCustomId('resource_description')
      .setLabel('Knowledge Description')
      .setStyle(TextInputStyle.Paragraph)
      .setPlaceholder('A brief description of this jungle knowledge')
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
        content: `❌ You must provide a reason for taking away this monkey's banana.`,
        ephemeral: true
      });
    }
    
    await interaction.deferReply({ ephemeral: true });
    
    if (!userDB || !userDB.verifiedUsers || !userDB.verifiedUsers[userId]) {
      return interaction.editReply({ 
        content: `❌ Monkey <@${userId}> doesn't have a banana.`
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
            .setTitle('🐵 MonkeyBytes Jungle Access Update')
            .setDescription(`Your banana has been taken by a monkey elder, revoking your access to the MonkeyBytes jungle.\n\n**Reason:** ${reason}\n\nTo regain access to our coding jungle, please [click here to request a new banana](${authUrl}). After you authenticate, a monkey elder will review your request.`)
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
          .setTitle('🍌 Banana Confiscated')
          .setDescription(`<@${userId}>'s banana has been taken by <@${interaction.user.id}>!`)
          .addFields(
            { name: 'Monkey ID', value: userId, inline: true },
            { name: 'Action By', value: `<@${interaction.user.id}>`, inline: true },
            { name: 'Reason', value: reason, inline: false }
          )
          .setColor('#FF0000')
          .setFooter({ text: config.embedFooter })
          .setTimestamp();
        
        await logChannel.send({ embeds: [embed] }).catch(() => {});
      }
      
      await interaction.editReply({ 
        content: `✅ Successfully taken <@${userId}>'s banana with reason: "${reason}"`
      });
    } catch (error) {
      logger.error(`Error during deauthorization for ${userId}`, error);
      
      await interaction.editReply({ 
        content: `❌ Error taking banana: ${error.message}`
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
        content: `❌ You must provide a violation type.`,
        ephemeral: true
      });
    }
    
    await interaction.deferReply({ ephemeral: true });
    
    try {
      const channel = interaction.channel;
      const message = await channel.messages.fetch(messageId).catch(() => null);
      
      if (!message) {
        return interaction.editReply({
          content: '❌ Error: Message not found. It may have swung away.'
        });
      }
      
      const logChannel = interaction.guild.channels.cache.get(config.logChannelId);
      if (logChannel) {
        const embed = new EmbedBuilder()
          .setTitle('⚠️ Jungle Rules Violation')
          .setDescription(`A message has been flagged as breaking jungle rules by <@${interaction.user.id}>`)
          .addFields(
            { name: 'Monkey', value: `<@${message.author.id}>`, inline: true },
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
        content: `✅ Message marked as "${violationType}" jungle rule violation. Monkey guards have been notified.`
      });
      
    } catch (error) {
      logger.error(`Error processing rule violation`, error);
      
      await interaction.editReply({
        content: `❌ Error processing jungle violation: ${error.message}`
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
        content: `❌ You must provide both a category and description for jungle knowledge.`,
        ephemeral: true
      });
    }
    
    await interaction.deferReply({ ephemeral: true });
    
    try {
      const channel = interaction.channel;
      const message = await channel.messages.fetch(messageId).catch(() => null);
      
      if (!message) {
        return interaction.editReply({
          content: '❌ Error: Message not found. It may have swung away.'
        });
      }
      
      const resourcesChannel = interaction.guild.channels.cache.get(config.resourcesChannelId);
      if (!resourcesChannel) {
        return interaction.editReply({
          content: '❌ Banana archive not found. Please set up a knowledge storage area first.'
        });
      }
      
      const embed = new EmbedBuilder()
        .setTitle(`${category} Jungle Resource`)
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
          .setTitle('📚 Jungle Knowledge Added')
          .setDescription(`A new resource has been added to the archives by <@${interaction.user.id}>`)
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
        content: `✅ Knowledge successfully added to the banana archives under category "${category}".`
      });
      
    } catch (error) {
      logger.error(`Error adding to resources`, error);
      
      await interaction.editReply({
        content: `❌ Error adding to jungle knowledge: ${error.message}`
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
      .setTitle('🕒 Jungle Bot Status')
      .addFields([
        { name: 'Bot Status', value: 'Swinging through vines', inline: true },
        { name: 'Time in Jungle', value: uptimeString, inline: true },
        { name: 'Banana Storage', value: `${memoryUsage} MB`, inline: true },
        { name: 'Jungle Connection', value: `${client.ws.ping}ms`, inline: true },
        { name: 'Jungle Time', value: `${uptimePercentage}%`, inline: true }
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
      .setTitle("🍌 MonkeyBytes Jungle Status")
      .setColor(config.embedColor)
      .addFields([
        {
          name: "Monkey Bot Status",
          value: `Swinging through vines | ${client.user.tag}`,
          inline: true
        },
        {
          name: "Banana Storage",
          value: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`,
          inline: true
        },
        {
          name: "Monkeys with Bananas",
          value: currentVerifiedCount.toString(),
          inline: true
        },
        {
          name: "Bananaless Monkeys",
          value: currentDeauthCount.toString(),
          inline: true
        },
        {
          name: "Pending Banana Requests",
          value: pendingCount.toString(),
          inline: true
        },
        {
          name: "Jungle Stats",
          value: `✅ ${userDB.statistics.totalVerified} bananas given | ❌ ${userDB.statistics.totalDeauths} bananas taken`,
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
          { name: 'Nap Duration', value: `${downtimeCheck.duration} minutes`, inline: true },
          { name: 'Nap Started', value: downtimeCheck.start.toLocaleString(), inline: true },
          { name: 'Woke Up', value: new Date().toLocaleString(), inline: true }
        );
      }
      
      const uptimePercentage = calculateUptimePercentage();
      fields.push({ name: 'Overall Uptime', value: `${uptimePercentage}%`, inline: true });
      
      const uptimeEmbed = new EmbedBuilder()
        .setTitle(downtimeCheck.detected ? '🔄 Monkey Awake After Nap' : '🍌 Monkey Bot Activated')
        .setDescription(downtimeCheck.detected 
          ? `MonkeyBytes Jungle Bot is now back online after taking a ${downtimeCheck.duration} minute nap.`
          : `MonkeyBytes Jungle Bot is now swinging through the vines and ready to help!`)
        .addFields(fields)
        .setColor(downtimeCheck.detected ? '#FFA500' : '#00FF00')
        .setFooter({ text: config.embedFooter })
        .setTimestamp();
        
      await uptimeLogsChannel.send({ embeds: [uptimeEmbed] });
    }
    
    // Start heartbeats and checks
    sendHeartbeat();
    sendUptimeUpdate();
    setInterval(sendHeartbeat, config.heartbeatInterval);
    setInterval(sendUptimeUpdate, 300000); // Send uptime logs every 5 minutes
    setInterval(async () => {
      if (!userDB.pendingApprovals || Object.keys(userDB.pendingApprovals).length === 0) return;
      await checkPendingApprovals();
    }, 30000);
    
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
    // Handle button interactions
    if (interaction.isButton()) {
      if (interaction.customId === 'verify_button') {
        if (userDB.verifiedUsers && userDB.verifiedUsers[interaction.user.id]) {
          return interaction.reply({
            content: '✅ You already have your banana! You\'re fully verified in the MonkeyBytes jungle.',
            ephemeral: true
          });
        }
        
        return sendVerificationUrl(interaction);
      }
      
      // Skip restart/stop button handlers as they use collectors
      if (interaction.customId.startsWith('confirm_') || interaction.customId.startsWith('cancel_')) {
        return;
      }
      
      // Handle approval/denial buttons
      if (interaction.customId.startsWith('approve_') || interaction.customId.startsWith('deny_')) {
        if (!isStaffMember(interaction.member)) {
          return interaction.reply({ 
            content: 'Only monkey elders (staff members) can use this command! 🍌',
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
            content: `✅ Successfully ${approved ? 'granted a banana to' : 'denied jungle access for'} <@${userId}>.`,
          });
          
          const updatedEmbed = EmbedBuilder.from(interaction.message.embeds[0])
            .setTitle(approved ? '✅ Banana Granted' : '❌ Banana Denied')
            .setDescription(`<@${userId}>'s banana request has been ${approved ? 'approved' : 'denied'} by <@${interaction.user.id}>.`)
            .setColor(approved ? config.embedColor : '#FF0000')
            .setTimestamp();
          
          await interaction.message.edit({ 
            embeds: [updatedEmbed],
            components: []
          }).catch(() => {});
        } else {
          await interaction.editReply({
            content: `❌ Error processing ${approved ? 'approval' : 'denial'}. Monkey might no longer be waiting.`,
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
            content: '✅ You already have your banana! You\'re fully verified in the MonkeyBytes jungle.',
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
      await handleModalSubmit(interaction);
    }
  } catch (error) {
    logger.error(`Error in interaction handler`, error);
    
    try {
      if (interaction.replied || interaction.deferred) {
        await interaction.editReply({
          content: `❌ There was a glitch in the jungle. Please try again later.`,
          ephemeral: true
        }).catch(() => {});
      } else {
        await interaction.reply({
          content: `❌ There was a glitch in the jungle. Please try again later.`,
          ephemeral: true
        }).catch(() => {});
      }
    } catch (replyError) {
      logger.error(`Failed to send error response`, replyError);
    }
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
            .setTitle('🛑 Monkey Going to Sleep')
            .setDescription('Monkey bot is going to sleep now. Good night!')
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
logger.startup('🍌 Starting MonkeyBytes Jungle Bot');
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