const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { Client, GatewayIntentBits, EmbedBuilder } = require('discord.js');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;

// In-memory storage (use database in production)
const pendingVerifications = new Map();
const verificationCodes = new Map();
const users = new Map();

// Discord Bot Setup
const discordClient = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.DirectMessages,
    GatewayIntentBits.MessageContent
  ]
});

discordClient.on('ready', () => {
  console.log(`Discord bot logged in as ${discordClient.user.tag}`);
  discordClient.user.setActivity('2FA verification', { type: 'WATCHING' });
});

discordClient.on('messageCreate', async (message) => {
  if (message.author.bot) return;
  if (!message.isDirect()) return;

  const content = message.content.trim();

  // !verify email@example.com
  if (content.startsWith('!verify ')) {
    const email = content.replace('!verify ', '').trim();

    // Check if this email has a pending verification
    if (!pendingVerifications.has(email)) {
      return message.reply('❌ No verification request found for this email. Start by logging in on the website.');
    }

    // Generate verification code
    const code = crypto.randomBytes(3).toString('hex').toUpperCase();
    const verificationData = {
      code,
      email,
      discordUserId: message.author.id,
      discordUsername: message.author.username,
      createdAt: Date.now(),
      expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
    };

    verificationCodes.set(email, verificationData);
    pendingVerifications.set(email, verificationData);

    // Send code to user
    const embed = new EmbedBuilder()
      .setColor('#7c3aed')
      .setTitle('🔐 Your 2FA Verification Code')
      .setDescription(`Your verification code is:\n\n\`\`\`${code}\`\`\``)
      .addFields(
        { name: '⏱️ Expires', value: 'In 10 minutes' },
        { name: '📧 Email', value: email, inline: true }
      )
      .setFooter({ text: 'Never share this code with anyone' });

    await message.reply({ embeds: [embed] });
    console.log(`Verification code sent to ${message.author.username} for ${email}`);
  }
});

discordClient.login(DISCORD_BOT_TOKEN);

// ============ API ROUTES ============

// 1. Initiate 2FA - User enters email
app.post('/api/auth/initiate-2fa', (req, res) => {
  const { email } = req.body;

  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  // Create or get user
  if (!users.has(email)) {
    users.set(email, { id: crypto.randomUUID(), email, createdAt: new Date() });
  }

  const user = users.get(email);
  const userId = user.id;

  // Mark as pending verification
  pendingVerifications.set(email, {
    userId,
    email,
    initiatedAt: Date.now(),
    expiresAt: Date.now() + 30 * 60 * 1000 // 30 minutes
  });

  res.json({
    userId,
    message: 'Verification initiated. Complete steps on the website.'
  });
});

// 2. Verify Discord connection
app.post('/api/auth/verify-discord', (req, res) => {
  const { userId, discordUsername } = req.body;

  if (!userId || !discordUsername) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // Find user by ID
  let userEmail;
  for (const [email, data] of pendingVerifications.entries()) {
    if (data.userId === userId) {
      userEmail = email;
      break;
    }
  }

  if (!userEmail) {
    return res.status(400).json({ error: 'Verification session expired' });
  }

  // Update verification data
  const verificationData = pendingVerifications.get(userEmail);
  verificationData.discordUsername = discordUsername;
  verificationData.discordVerifiedAt = Date.now();

  res.json({
    success: true,
    message: 'Discord username registered. Waiting for code...'
  });
});

// 3. Verify code from Discord DM
app.post('/api/auth/verify-code', (req, res) => {
  const { userId, code } = req.body;

  if (!userId || !code) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // Find user and verification data
  let userEmail;
  let verificationData;

  for (const [email, data] of verificationCodes.entries()) {
    if (data.email === email && data.code === code.toUpperCase()) {
      userEmail = email;
      verificationData = data;
      break;
    }
  }

  if (!verificationData) {
    return res.status(401).json({ error: 'Invalid verification code' });
  }

  // Check if expired
  if (Date.now() > verificationData.expiresAt) {
    verificationCodes.delete(userEmail);
    pendingVerifications.delete(userEmail);
    return res.status(401).json({ error: 'Verification code expired' });
  }

  // Verification successful
  const user = users.get(userEmail);
  user.discordUserId = verificationData.discordUserId;
  user.discordUsername = verificationData.discordUsername;
  user.verifiedAt = new Date();

  // Generate JWT token
  const token = jwt.sign(
    {
      userId: user.id,
      email: userEmail,
      discordUsername: user.discordUsername
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  // Clean up verification data
  verificationCodes.delete(userEmail);
  pendingVerifications.delete(userEmail);

  res.json({
    success: true,
    token,
    user: {
      id: user.id,
      email: userEmail,
      discordUsername: user.discordUsername
    }
  });
});

// 4. Verify token (for protected routes)
app.post('/api/auth/verify-token', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ valid: true, user: decoded });
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
});

// 5. Get user info (protected)
app.get('/api/user/profile', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = users.get(decoded.email);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      id: user.id,
      email: decoded.email,
      discordUsername: user.discordUsername,
      verifiedAt: user.verifiedAt,
      createdAt: user.createdAt
    });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// 6. Logout (optional, just for tracking)
app.post('/api/auth/logout', (req, res) => {
  const { token } = req.body;
  // In production, add token to a blacklist
  res.json({ success: true, message: 'Logged out successfully' });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', botReady: discordClient.isReady() });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Auth server running on http://localhost:${PORT}`);
  console.log(`📋 API documentation:`);
  console.log(`   POST /api/auth/initiate-2fa - Start verification`);
  console.log(`   POST /api/auth/verify-discord - Link Discord account`);
  console.log(`   POST /api/auth/verify-code - Submit verification code`);
  console.log(`   POST /api/auth/verify-token - Check token validity`);
  console.log(`   GET  /api/user/profile - Get user info (requires token)`);
});

module.exports = app;
