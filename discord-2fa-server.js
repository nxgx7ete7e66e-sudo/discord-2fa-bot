const express = require('express');
const cors = require('cors');
const { Client, GatewayIntentBits, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;

// In-memory store: userId -> { discordId, verified, expiresAt }
const pendingSessions = new Map();

// Discord Bot
const discordClient = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.DirectMessages,
    GatewayIntentBits.MessageContent
  ]
});

discordClient.on('clientReady', () => {
  console.log(`✅ Discord bot logged in as ${discordClient.user.tag}`);
});

// Handle Authenticate button click
discordClient.on('interactionCreate', async (interaction) => {
  if (!interaction.isButton()) return;
  if (!interaction.customId.startsWith('auth_')) return;

  const userId = interaction.customId.replace('auth_', '');
  const session = pendingSessions.get(userId);

  if (!session) {
    return interaction.reply({ content: '❌ Session expired or not found. Please log in again.', ephemeral: true });
  }

  if (Date.now() > session.expiresAt) {
    pendingSessions.delete(userId);
    return interaction.reply({ content: '❌ This verification request has expired. Please log in again.', ephemeral: true });
  }

  // Mark verified
  session.verified = true;
  pendingSessions.set(userId, session);

  // Update the message
  const successEmbed = new EmbedBuilder()
    .setColor('#57f287')
    .setTitle('✅ Authentication Successful')
    .setDescription('You have been verified. You can now return to the website — you will be logged in automatically.')
    .setFooter({ text: 'UH SERVICES • Security' })
    .setTimestamp();

  await interaction.update({ embeds: [successEmbed], components: [] });
  console.log(`✅ User ${userId} authenticated via Discord`);
});

// ── API ROUTES ──────────────────────────────────────────────────────────────

// POST /api/auth/initiate-2fa
// Body: { email, discordId }  (discordId = 17-18 digit Discord User ID)
app.post('/api/auth/initiate-2fa', async (req, res) => {
  const { email, discordId } = req.body;

  if (!email || !discordId) {
    return res.status(400).json({ message: 'Email and discordId are required.' });
  }

  const userId = crypto.randomUUID();
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

  pendingSessions.set(userId, { email, discordId, verified: false, expiresAt });

  // Try to DM the user
  try {
    const discordUser = await discordClient.users.fetch(discordId);

    const embed = new EmbedBuilder()
      .setColor('#f59e0b')
      .setTitle('🔐 Two-Factor Authentication Required')
      .setDescription(`A login attempt was made on **UHSERVICES.GG**.\n\nClick the button below to verify it's you.`)
      .addFields({ name: '📧 Account', value: email, inline: true })
      .setFooter({ text: 'This request expires in 10 minutes • UH SERVICES' })
      .setTimestamp();

    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId(`auth_${userId}`)
        .setLabel('Authenticate')
        .setStyle(ButtonStyle.Success)
        .setEmoji('🔑')
    );

    await discordUser.send({ embeds: [embed], components: [row] });
    console.log(`📨 Sent DM to Discord user ${discordId} for ${email}`);

    return res.json({ userId, message: 'Verification DM sent.' });

  } catch (err) {
    console.error(`❌ Failed to DM Discord user ${discordId}:`, err.message);
    pendingSessions.delete(userId);

    let message = 'Failed to send Discord DM. Make sure you are in the UH SERVICES server.';
    if (err.code === 50007) message = 'Cannot send DM — please enable DMs from server members in your Discord privacy settings.';
    if (err.code === 10013) message = 'Discord User ID not found. Double-check the ID in your Security settings.';

    return res.status(488).json({ message });
  }
});

// POST /api/auth/verify-token
// Body: { userId }  — poll this to check if user clicked Authenticate
app.post('/api/auth/verify-token', (req, res) => {
  const { userId } = req.body;

  if (!userId) return res.status(400).json({ error: 'Missing userId' });

  const session = pendingSessions.get(userId);

  if (!session) return res.json({ verified: false, error: 'Session not found' });
  if (Date.now() > session.expiresAt) {
    pendingSessions.delete(userId);
    return res.json({ verified: false, error: 'Session expired' });
  }

  if (session.verified) {
    pendingSessions.delete(userId); // clean up after success
    return res.json({ verified: true });
  }

  return res.json({ verified: false });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', botReady: discordClient.isReady() });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Auth server running on port ${PORT}`);
});

if (!DISCORD_BOT_TOKEN) {
  console.error('❌ DISCORD_BOT_TOKEN missing!');
  process.exit(1);
}

discordClient.login(DISCORD_BOT_TOKEN);

module.exports = app;
