const { Client, GatewayIntentBits, EmbedBuilder, PermissionsBitField, ActivityType } = require('discord.js');

// TOKEN langsung di sini
const TOKEN = "";

// Channel IDs yang diizinkan untuk share link
const ALLOWED_CHANNELS = [
    '1275433041484972055',
    '1281271611898462300',
    '1278597288696086538',
    '1333400998571544616',
    '1398614852100161677',
    '1384468602488623165',
    '1384468520326266961',
    '1347042916333522965'
];

// Channel ID untuk logs
const LOG_CHANNEL_ID = '1403631745319964724';

// Regex untuk mendeteksi link Discord server
const DISCORD_SERVER_REGEX = /(https?:\/\/)?(discord\.(gg|com)\/(invite\/)?[^\s]+)|(discordapp\.com\/invite\/[^\s]+)/i;

// Regex untuk platform yang diizinkan
const ALLOWED_PLATFORMS_REGEX = /(https?:\/\/)?(open\.spotify\.com|spotify\.com|youtube\.com|youtu\.be|tiktok\.com|instagram\.com|facebook\.com|twitter\.com|x\.com|reddit\.com|github\.com)/i;

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.GuildMembers
    ]
});

client.once('ready', () => {
    console.log(`✅ ${client.user.tag} siap memantau link!`);
    
    client.user.setPresence({
        activities: [{ name: 'PREMAN #ANTILINK', type: ActivityType.Playing }],
        status: 'online'
    });
});

client.on('messageCreate', async (message) => {
    try {
        if (message.author.bot) return;
        if (!message.content) return;

        // Cek apakah ada link Discord server
        const hasDiscordServerLink = DISCORD_SERVER_REGEX.test(message.content);
        
        // Jika tidak ada link Discord server, skip
        if (!hasDiscordServerLink) return;

        const member = message.member;
        const channel = message.channel;
        const isAdmin = member.permissions.has(PermissionsBitField.Flags.Administrator);
        const isOwner = message.guild.ownerId === message.author.id;
        const isAllowedChannel = ALLOWED_CHANNELS.includes(channel.id);

        // Hanya blokir link Discord server, link lain diizinkan
        if (!isAdmin && !isOwner && !isAllowedChannel) {
            await message.delete();

            // Pesan gaul di channel terlarang
            const replyEmbed = new EmbedBuilder()
                .setColor('#ff0066')
                .setDescription(`🚫 Woi ${message.author}, jangan share link Discord server di sini dong! 😎  
Link Discord cuma boleh di channel yang udah disediain, bro! Link lain kayak Spotify, YouTube, TikTok masih boleh kok!`);
            
            await message.channel.send({
                content: `${message.author}`,
                embeds: [replyEmbed]
            });

            // Log channel dengan info + aturan
            const logChannel = message.guild.channels.cache.get(LOG_CHANNEL_ID);
            if (logChannel) {
                const logEmbed = new EmbedBuilder()
                    .setColor('#ff6600')
                    .setTitle('🗑️ Link Terhapus')
                    .setDescription(`Pesan berisi link telah dihapus otomatis.`)
                    .addFields(
                        { name: 'User', value: `${message.author} (${message.author.tag})`, inline: true },
                        { name: 'Channel', value: `${channel}`, inline: true },
                        { name: 'Isi Pesan', value: message.content.length > 1000 ? message.content.substring(0, 1000) + '...' : message.content },
                        { name: 'Waktu', value: `<t:${Math.floor(Date.now() / 1000)}:F>` },
                        { name: 'Aturan Channel', value: `Sharing link hanya diperbolehkan di:  
${ALLOWED_CHANNELS.map(id => `<#${id}>`).join(', ')}` }
                    )
                    .setThumbnail(message.author.displayAvatarURL())
                    .setTimestamp();

                await logChannel.send({ content: `${message.author}`, embeds: [logEmbed] });
            }

            console.log(`Link terhapus dari ${message.author.tag} di #${channel.name}`);
        }
    } catch (error) {
        console.error('Error saat memproses pesan:', error);
    }
});

// Handler error global
client.on('error', console.error);
client.on('shardError', console.error);
process.on('unhandledRejection', (reason) => {
    console.error('Unhandled promise rejection:', reason);
});

client.login(TOKEN)
    .then(() => console.log('🔑 Bot berhasil login!'))
    .catch((err) => console.error('❌ Gagal login bot:', err));
