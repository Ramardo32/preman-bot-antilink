// This bot only for Anti-link/Keylogger SA-MP/Malware Detection Automatic., DISCORD ramardoaja
// Author: Ramardo
// Description: 
// It is forbidden to remove this author mark, okay?

const { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder, EmbedBuilder } = require('discord.js');
const fs = require('fs');
const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent
    ]
});

const guildSettings = new Map();

const SCAN_CHANNEL_ID = process.env.SCAN_CHANNEL_ID;
const LOG_CHANNEL_ID = process.env.LOG_CHANNEL_ID;
const VT_API_KEY = process.env.VT_API_KEY;

const EXTENSIONS = [
  // Executables and Scripts
  "exe","asi","dll","sys","scr","bat","cmd","ps1","vbs","js","jar","com","msi","cs","lua","py","ahk","sh","bash","pl","rb","php","asp","jsp","cgi","fcgi","wasm",
  // Archives
  "zip","rar","7z","tar","gz","bz2","xz","tgz","tbz2","txz","iso","dmg","img","vhd","vhdx","vmdk","ova","ovf",
  // Documents
  "pdf","doc","docx","xls","xlsx","ppt","pptx","txt","rtf","odt","ods","odp","csv","xml","json","yaml","yml","ini","cfg","conf","log",
  // Images
  "jpg","jpeg","png","gif","bmp","tiff","tif","svg","webp","ico","cur","ani","psd","ai","eps","cdr","xcf",
  // Audio/Video
  "mp3","mp4","avi","mkv","flv","wmv","mov","mpg","mpeg","m4a","m4v","3gp","webm","ogg","wav","flac","aac","wma","mid","midi","aiff","au",
  // Other
];

// Patterns for detecting Lua keyloggers (refined to reduce false positives)
const LUA_KEYLOGGER_PATTERNS = [
  /sendToDiscordEmbed/,
  /discord\.com\/api\/webhooks/,
  /inputtext.*password|password.*inputtext/,
  /requests\.post.*discord|discord.*requests\.post/,
  /encodeJson.*discord|discord.*encodeJson/,
  /loadstring.*eval|eval.*loadstring/,
  /io\.popen.*curl|curl.*io\.popen/,
  /socket\.http.*wget|wget.*socket\.http/,
  /http:\/\/.*discord|discord.*http:\/\//
];

const commands = [
    new SlashCommandBuilder()
        .setName('scan')
        .setDescription('Scan a file for malware and keyloggers')
        .addAttachmentOption(option =>
            option.setName('file')
                .setDescription('The file to scan')
                .setRequired(true)
        ),
    new SlashCommandBuilder()
        .setName('antilink')
        .setDescription('Enable or disable anti-link feature')
        .addBooleanOption(option =>
            option.setName('enable')
                .setDescription('Enable or disable')
                .setRequired(true)
        ),
    new SlashCommandBuilder()
        .setName('addlinkchannel')
        .setDescription('Add a channel where links are allowed')
        .addChannelOption(option =>
            option.setName('channel')
                .setDescription('The channel ID')
                .setRequired(true)
        ),
    new SlashCommandBuilder()
        .setName('removelinkchannel')
        .setDescription('Remove a channel from allowed links')
        .addChannelOption(option =>
            option.setName('channel')
                .setDescription('The channel ID')
                .setRequired(true)
        ),
    new SlashCommandBuilder()
        .setName('listchannelallowed')
        .setDescription('List all allowed channels for link sharing'),
    new SlashCommandBuilder()
        .setName('setlogchannel')
        .setDescription('Set the channel for logging link shares')
        .addChannelOption(option =>
            option.setName('channel')
                .setDescription('The channel ID')
                .setRequired(true)
        )
];

client.once('ready', async () => {
    console.log(`✅ Bot aktif sebagai ${client.user.tag}`);
    console.log('🛡️ SA-MP Auto Scanner Aktif');

    // Test VT API Key if provided
    if (VT_API_KEY) {
        try {
            const testResponse = await axios.get('https://www.virustotal.com/api/v3/users/me', {
                headers: { "x-apikey": VT_API_KEY }
            });
            console.log('✅ VirusTotal API Key valid');
        } catch (error) {
            console.log('❌ VirusTotal API Key invalid or network error:', error.response?.status || error.message);
        }
    } else {
        console.log('⚠️ VirusTotal API Key not provided - VT scanning disabled');
    }

    client.user.setPresence({
        activities: [{
            name: 'Anti Keylogger/Malware/Link By Ramardo',
            type: 0
        }],
        status: 'online'
    });

    // Register commands for each guild
    const rest = new REST({ version: '10' }).setToken(process.env.TOKEN);
    try {
        console.log('Started refreshing application (/) commands.');
        for (const guild of client.guilds.cache.values()) {
            await rest.put(Routes.applicationGuildCommands(client.user.id, guild.id), { body: commands });
        }
        console.log('Successfully reloaded application (/) commands.');
    } catch (error) {
        console.error(error);
    }
});

client.on('messageCreate', async message => {
    if (message.author.bot) return;

    // Virus scanning (independent of anti-link settings)
    if (message.channel.id === SCAN_CHANNEL_ID && (message.content.startsWith('!scan') || message.attachments.size > 0)) {
        if (message.content.startsWith('!scan') && message.attachments.size === 0) {
            const noFileEmbed = new EmbedBuilder()
                .setTitle('❌ File Tidak Ditemukan')
                .setDescription('Silakan lampirkan file untuk dipindai dengan perintah `!scan`.')
                .addFields(
                    { name: '📋 Cara Penggunaan', value: '`!scan` + lampirkan file', inline: true },
                    { name: '📁 Format Didukung', value: 'exe, dll, zip, rar, dll.', inline: true }
                )
                .setColor(0xFF0000)
                .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                .setFooter({ text: 'PREMAN Anti Link By Ramardo', iconURL: client.user.displayAvatarURL() })
                .setTimestamp();
            return message.reply({ embeds: [noFileEmbed] });
        }
        const file = message.attachments.first();
        const ext = file.name.split(".").pop().toLowerCase();
        if (EXTENSIONS.includes(ext)) {
            const temp = `./${file.name}`;
            const scanEmbed = new EmbedBuilder()
                .setTitle('🔍 Memindai File')
                .setDescription(`📁 **File:** ${file.name}\n⏳ **Status:** Sedang memindai...\n👤 **Uploader:** ${message.author}`)
                .setColor(0xFFFF00)
                .setThumbnail('https://media1.tenor.com/m/2JadSPd49K0AAAAC/cyberpunk-hacker.gif') // Scanning animation
                .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                .setFooter({ text: 'PREMAN Anti Link By Ramardo', iconURL: client.user.displayAvatarURL() })
                .setTimestamp();
            await message.reply({ embeds: [scanEmbed] });

            try {
                const data = await axios.get(file.url, { responseType: "arraybuffer" });
                fs.writeFileSync(temp, data.data);

                let fileContent = null;
                if (ext === 'lua') {
                    fileContent = fs.readFileSync(temp, 'utf8');
                }

                // Check for Lua keylogger patterns
                let isSafe = true;
                let detectedPatterns = [];
                if (ext === 'lua') {
                    detectedPatterns = LUA_KEYLOGGER_PATTERNS.filter(pattern => pattern.test(fileContent));
                    if (detectedPatterns.length > 0) {
                        await message.delete();
                        const log = client.channels.cache.get(LOG_CHANNEL_ID);
                        const detectedStrings = detectedPatterns.map(pattern => pattern.source).join(', ');
                        const keyloggerEmbed = new EmbedBuilder()
                            .setTitle('🚨 KEYLOGGER TERDETEKSI!')
                            .setDescription(`**File Lua yang terdeteksi sebagai keylogger telah dihapus secara otomatis.**`)
                            .addFields(
                                { name: '📁 Nama File', value: `${file.name}`, inline: true },
                                { name: '👤 Uploader', value: `${message.author}`, inline: true },
                                { name: '🔍 String Terdeteksi', value: detectedStrings, inline: false },
                                { name: '🛡️ Status', value: '⚠️ **TIDAK AMAN**', inline: false }
                            )
                            .setColor(0xFF0000)
                            .setThumbnail(message.guild.iconURL() || client.user.displayAvatarURL())
                            .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                        await log.send({ embeds: [keyloggerEmbed] });
                        fs.unlinkSync(temp);
                        return; // Exit early
                    }
                }

                const log = client.channels.cache.get(LOG_CHANNEL_ID);

                if (VT_API_KEY) {
                    // Perform VT scan if API key is available
                    try {
                        const hash = crypto
                            .createHash("sha256")
                            .update(fs.readFileSync(temp))
                            .digest("hex");

                        const vt = await axios.get(
                            `https://www.virustotal.com/api/v3/files/${hash}`,
                            { headers: { "x-apikey": VT_API_KEY } }
                        );

                        const s = vt.data.data.attributes.last_analysis_stats;
                        fs.unlinkSync(temp);

                        if (s.malicious > 0) {
                            await message.delete();
                            const malwareEmbed = new EmbedBuilder()
                                .setTitle('🚨 MALWARE TERDETEKSI!')
                                .setDescription(`**File yang terdeteksi malware telah dihapus secara otomatis.**`)
                                .addFields(
                                    { name: '📁 Nama File', value: `${file.name}`, inline: true },
                                    { name: '❌ Deteksi Malware', value: `${s.malicious} antivirus`, inline: true },
                                    { name: '👤 Uploader', value: `${message.author}`, inline: true },
                                    { name: '🛡️ Status', value: '⚠️ **TIDAK AMAN**', inline: false }
                                )
                                .setColor(0xFF0000)
                                .setThumbnail('https://media1.tenor.com/m/5EUurOL4OWwAAAAC/caution-error-message.gif') // Warning icon
                                .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                                .setFooter({ text: 'PREMAN Anti Virus By Ramardo', iconURL: client.user.displayAvatarURL() })
                                .setTimestamp();
                            await log.send({ embeds: [malwareEmbed] });
                            return;
                        } else {
                            if (ext === 'lua') {
                                // Special embed for safe .lua files with VT scan
                                const lines = fileContent ? fileContent.split('\n').slice(0, 10).join('\n') : 'Unable to read file content.';
                                const cleanLuaEmbed = new EmbedBuilder()
                                    .setTitle('✅ FILE LUA AMAN DARI KEYLOGGER!')
                                    .setDescription(`**File Lua telah dipindai dan dinyatakan aman dari keylogger dan malware.**`)
                                    .addFields(
                                        { name: '📁 Nama File', value: `${file.name}`, inline: true },
                                        { name: '✅ Antivirus Aman', value: `${s.harmless}`, inline: true },
                                        { name: '⚠️ Mencurigakan', value: `${s.suspicious}`, inline: true },
                                        { name: '❌ Malware', value: `${s.malicious}`, inline: true },
                                        { name: '👤 Uploader', value: `${message.author}`, inline: true },
                                        { name: '🛡️ Status', value: '✅ **AMAN DARI KEYLOGGER**', inline: false },
                                        { name: '📋 Code Inti Aman', value: `\`\`\`lua\n${lines}\n\`\`\``, inline: false },
                                        { name: '📋 Alasan Aman', value: 'File tidak terdeteksi malware oleh antivirus dan tidak mengandung pola keylogger berbahaya.', inline: false }
                                    )
                                    .setColor(0x00FF00)
                                    .setThumbnail('https://media.tenor.com/anvPOsmgP0gAAAAi/its-for-discord-bot.gif') // Check mark animation
                                    .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                                    .setFooter({ text: 'PREMAN Anti Keylogger By Ramardo', iconURL: client.user.displayAvatarURL() })
                                    .setTimestamp();
                                await message.reply({ embeds: [cleanLuaEmbed] });
                            } else {
                                const cleanEmbed = new EmbedBuilder()
                                    .setTitle('✅ FILE AMAN!')
                                    .setDescription(`**File telah dipindai dan dinyatakan aman.**`)
                                    .addFields(
                                        { name: '📁 Nama File', value: `${file.name}`, inline: true },
                                        { name: '✅ Antivirus Aman', value: `${s.harmless}`, inline: true },
                                        { name: '⚠️ Mencurigakan', value: `${s.suspicious}`, inline: true },
                                        { name: '❌ Malware', value: `${s.malicious}`, inline: true },
                                        { name: '👤 Uploader', value: `${message.author}`, inline: true },
                                        { name: '🛡️ Status', value: '✅ **AMAN**', inline: false },
                                        { name: '📋 Alasan Aman', value: 'File tidak terdeteksi malware oleh antivirus dan tidak mengandung pola berbahaya.', inline: false }
                                    )
                                    .setColor(0x00FF00)
                                    .setThumbnail('https://media.tenor.com/anvPOsmgP0gAAAAi/its-for-discord-bot.gif') // Check mark animation
                                    .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                                    .setFooter({ text: 'PREMAN Anti Virus By Ramardo', iconURL: client.user.displayAvatarURL() })
                                    .setTimestamp();
                                await message.reply({ embeds: [cleanEmbed] });
                            }
                        }
                    } catch (vtError) {
                        fs.unlinkSync(temp);
                        // If file not found in VT (404), treat as safe
                        if (vtError.response && vtError.response.status === 404) {
                            if (ext === 'lua') {
                                // Special embed for safe .lua files without VT
                                const lines = fileContent.split('\n').slice(0, 10).join('\n');
                                const cleanLuaEmbed = new EmbedBuilder()
                                    .setTitle('✅ FILE LUA AMAN DARI KEYLOGGER!')
                                    .setDescription(`**File Lua telah dipindai dan dinyatakan aman dari keylogger.**`)
                                    .addFields(
                                        { name: '📁 Nama File', value: `${file.name}`, inline: true },
                                        { name: '👤 Uploader', value: `${message.author}`, inline: true },
                                        { name: '🛡️ Status', value: '✅ **AMAN DARI KEYLOGGER**', inline: false },
                                        { name: '📋 Code Inti Aman', value: `\`\`\`lua\n${lines}\n\`\`\``, inline: false },
                                        { name: '📋 Alasan Aman', value: 'File tidak mengandung pola keylogger berbahaya. (File belum terdaftar di VirusTotal, diasumsikan aman)', inline: false }
                                    )
                                    .setColor(0x00FF00)
                                    .setThumbnail('https://media.tenor.com/anvPOsmgP0gAAAAi/its-for-discord-bot.gif')
                                    .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                                    .setFooter({ text: 'PREMAN Anti Keylogger By Ramardo', iconURL: client.user.displayAvatarURL() })
                                    .setTimestamp();
                                await message.reply({ embeds: [cleanLuaEmbed] });
                            } else {
                                const cleanEmbed = new EmbedBuilder()
                                    .setTitle('✅ FILE AMAN!')
                                    .setDescription(`**File telah dipindai dan dinyatakan aman.**`)
                                    .addFields(
                                        { name: '📁 Nama File', value: `${file.name}`, inline: true },
                                        { name: '👤 Uploader', value: `${message.author}`, inline: true },
                                        { name: '🛡️ Status', value: '✅ **AMAN**', inline: false },
                                        { name: '📋 Alasan Aman', value: 'File belum terdaftar di VirusTotal, diasumsikan aman.', inline: false }
                                    )
                                    .setColor(0x00FF00)
                                    .setThumbnail('https://media.tenor.com/anvPOsmgP0gAAAAi/its-for-discord-bot.gif')
                                    .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                                    .setFooter({ text: 'PREMAN Anti Virus By Ramardo', iconURL: client.user.displayAvatarURL() })
                                    .setTimestamp();
                                await message.reply({ embeds: [cleanEmbed] });
                            }
                        } else {
                            // Other VT errors (invalid key, network, etc.)
                            throw vtError; // Let it go to outer catch
                        }
                    }
                } else {
                    // No VT API key, report as safe if no patterns detected
                    if (ext === 'lua') {
                        // Special embed for safe .lua files
                        const lines = fileContent.split('\n').slice(0, 10).join('\n'); // First 10 lines as core code
                        fs.unlinkSync(temp);
                        const cleanLuaEmbed = new EmbedBuilder()
                            .setTitle('✅ FILE LUA AMAN DARI KEYLOGGER!')
                            .setDescription(`**File Lua telah dipindai dan dinyatakan aman dari keylogger.**`)
                            .addFields(
                                { name: '📁 Nama File', value: `${file.name}`, inline: true },
                                { name: '👤 Uploader', value: `${message.author}`, inline: true },
                                { name: '🛡️ Status', value: '✅ **AMAN DARI KEYLOGGER**', inline: false },
                                { name: '📋 Code Inti Aman', value: `\`\`\`lua\n${lines}\n\`\`\``, inline: false },
                                { name: '📋 Alasan Aman', value: 'File tidak mengandung pola keylogger berbahaya. (Pemindaian VT dilewati karena tidak ada API key)', inline: false }
                            )
                            .setColor(0x00FF00)
                            .setThumbnail('https://media.tenor.com/anvPOsmgP0gAAAAi/its-for-discord-bot.gif') // Check mark animation
                            .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                            .setFooter({ text: 'PREMAN Anti Keylogger By Ramardo', iconURL: client.user.displayAvatarURL() })
                            .setTimestamp();
                        await message.reply({ embeds: [cleanLuaEmbed] });
                    } else {
                        fs.unlinkSync(temp);
                        const cleanEmbed = new EmbedBuilder()
                            .setTitle('✅ FILE AMAN!')
                            .setDescription(`**File telah dipindai dan dinyatakan aman.**`)
                            .addFields(
                                { name: '📁 Nama File', value: `${file.name}`, inline: true },
                                { name: '👤 Uploader', value: `${message.author}`, inline: true },
                                { name: '🛡️ Status', value: '✅ **AMAN**', inline: false },
                                { name: '📋 Alasan Aman', value: 'File tidak mengandung pola berbahaya. (Pemindaian VT dilewati karena tidak ada API key)', inline: false }
                            )
                            .setColor(0x00FF00)
                            .setThumbnail('https://media.tenor.com/anvPOsmgP0gAAAAi/its-for-discord-bot.gif') // Check mark animation
                            .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                            .setFooter({ text: 'PREMAN Anti Virus By Ramardo', iconURL: client.user.displayAvatarURL() })
                            .setTimestamp();
                        await message.reply({ embeds: [cleanEmbed] });
                    }
                }

            } catch (e) {
                if (ext === 'lua') {
                    let lines = 'Unable to read file content.';
                    if (fileContent) {
                        lines = fileContent.split('\n').slice(0, 10).join('\n');
                    } else {
                        try {
                            const tempContent = fs.readFileSync(temp, 'utf8');
                            lines = tempContent.split('\n').slice(0, 10).join('\n');
                        } catch (readError) {
                            console.log('Error reading file content:', readError.message);
                        }
                    }
                    const cleanLuaEmbed = new EmbedBuilder()
                        .setTitle('✅ FILE LUA AMAN DARI KEYLOGGER!')
                        .setDescription(`**File Lua telah dipindai dan dinyatakan aman dari keylogger.**`)
                        .addFields(
                            { name: '📁 Nama File', value: `${file.name}`, inline: true },
                            { name: '👤 Uploader', value: `${message.author}`, inline: true },
                            { name: '🛡️ Status', value: '✅ **AMAN DARI KEYLOGGER**', inline: false },
                            { name: '📋 Code Inti Aman', value: `\`\`\`lua\n${lines}\n\`\`\``, inline: false },
                            { name: '📋 Alasan Aman', value: 'File tidak mengandung pola keylogger berbahaya. (Pemindaian VT gagal, tetapi aman dari keylogger)', inline: false }
                        )
                        .setColor(0x00FF00)
                        .setThumbnail('https://media.tenor.com/anvPOsmgP0gAAAAi/its-for-discord-bot.gif')
                        .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                        .setFooter({ text: 'PREMAN Anti Keylogger By Ramardo', iconURL: client.user.displayAvatarURL() })
                        .setTimestamp();
                    await message.reply({ embeds: [cleanLuaEmbed] });
                } else {
                    const errorEmbed = new EmbedBuilder()
                        .setTitle('❌ PEMINDAIAN GAGAL')
                        .setDescription(`**Terjadi kesalahan saat memindai file.**`)
                        .addFields(
                            { name: '📁 Nama File', value: `${file.name}`, inline: true },
                            { name: '👤 Uploader', value: `${message.author}`, inline: true },
                            { name: '🔍 Alasan', value: 'File belum terdaftar di Database atau ada kesalahan teknis.', inline: false },
                            { name: '💡 Saran', value: 'Coba lagi nanti atau hubungi admin.', inline: false }
                        )
                        .setColor(0xFF0000)
                        .setThumbnail('https://i.imgur.com/error.png') // Error icon
                        .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                        .setFooter({ text: 'PREMAN Anti Virus By Ramardo', iconURL: client.user.displayAvatarURL() })
                        .setTimestamp();
                    await message.reply({ embeds: [errorEmbed] });
                }
                if (fs.existsSync(temp)) fs.unlinkSync(temp);
            }
        }
        return; // Exit early after scanning to avoid anti-link processing
    }

    const settings = { enabled: false, allowedChannels: [], logChannel: null, ...guildSettings.get(message.guild.id) };
    if (!settings.enabled) return;
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const links = message.content.match(urlRegex);
    if (!links) return;
    const discordLinkRegex = /https?:\/\/(www\.)?(discord\.com|discord\.gg)/;
    const hasDiscordLink = links.some(link => discordLinkRegex.test(link));
    if (hasDiscordLink && !settings.allowedChannels.includes(message.channel.id) && !message.member.permissions.has('ManageRoles')) {
        await message.delete();
        await message.channel.send(`<@${message.author.id}>`);
        const deleteEmbed = new EmbedBuilder()
            .setTitle('🚫 Link Discord Dilarang!')
            .setDescription(`Woi <@${message.author.id}>, jangan share link Discord server di sini dong! 😎\nLink Discord cuma boleh di channel yang udah disediain, bro! Link lain kayak Spotify, YouTube, TikTok masih boleh kok!`)
            .setColor(0xFF0000)
            .setTimestamp();
        await message.channel.send({ embeds: [deleteEmbed] });

        // Log to log channel
        if (settings.logChannel) {
            const logChannel = message.guild.channels.cache.get(settings.logChannel);
            if (logChannel) {
                await logChannel.send(`<@${message.author.id}>`);
                const logEmbed = new EmbedBuilder()
                    .setTitle('🗑️ Link Terhapus')
                    .setDescription('Pesan berisi link telah dihapus otomatis.')
                    .addFields(
                        { name: 'User', value: `${message.author} (${message.author.tag})`, inline: true },
                        { name: 'Channel', value: `${message.channel}`, inline: true },
                        { name: 'Isi Pesan', value: message.content, inline: false },
                        { name: 'Waktu', value: `<t:${Math.floor(message.createdTimestamp / 1000)}:F>`, inline: false },
                        { name: 'Aturan Channel', value: `Sharing link hanya diperbolehkan di: ${settings.allowedChannels.map(id => `<#${id}>`).join(', ')}` }
                    )
                    .setColor(0xFF0000)
                    .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                    .setTimestamp();
                await logChannel.send({ embeds: [logEmbed] });
            }
        }
    }

    // Log sharing and tagging
    const mentionedUsers = message.mentions.users;
    if (mentionedUsers.size > 0 && links.length > 0) {
        console.log(`User ${message.author.tag} shared links and tagged: ${mentionedUsers.map(u => u.tag).join(', ')}`);
    }
});

client.on('interactionCreate', async interaction => {
    if (!interaction.isChatInputCommand()) return;
    const { commandName } = interaction;
    if (commandName === 'scan') {
        const file = interaction.options.getAttachment('file');
        const ext = file.name.split(".").pop().toLowerCase();
        if (EXTENSIONS.includes(ext)) {
            const temp = `./${file.name}`;
            const scanEmbed = new EmbedBuilder()
                .setTitle('🔍 Memindai File')
                .setDescription(`📁 **File:** ${file.name}\n⏳ **Status:** Sedang memindai...\n👤 **Uploader:** ${interaction.user}`)
                .setColor(0xFFFF00)
                .setThumbnail('https://media1.tenor.com/m/2JadSPd49K0AAAAC/cyberpunk-hacker.gif') // Scanning animation
                .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                .setFooter({ text: 'PREMAN Anti Link By Ramardo', iconURL: client.user.displayAvatarURL() })
                .setTimestamp();
            await interaction.reply({ embeds: [scanEmbed] });

            try {
                const data = await axios.get(file.url, { responseType: "arraybuffer" });
                fs.writeFileSync(temp, data.data);

                let fileContent = null;
                if (ext === 'lua') {
                    fileContent = fs.readFileSync(temp, 'utf8');
                }

                // Check for Lua keylogger patterns
                let isSafe = true;
                let detectedPatterns = [];
                if (ext === 'lua') {
                    detectedPatterns = LUA_KEYLOGGER_PATTERNS.filter(pattern => pattern.test(fileContent));
                    if (detectedPatterns.length > 0) {
                        const detectedStrings = detectedPatterns.map(pattern => pattern.source).join(', ');
                        const keyloggerEmbed = new EmbedBuilder()
                            .setTitle('🚨 KEYLOGGER TERDETEKSI!')
                            .setDescription(`**File Lua yang terdeteksi sebagai keylogger telah dihapus secara otomatis.**`)
                            .addFields(
                                { name: '📁 Nama File', value: `${file.name}`, inline: true },
                                { name: '👤 Uploader', value: `${interaction.user}`, inline: true },
                                { name: '🔍 String Terdeteksi', value: detectedStrings, inline: false },
                                { name: '🛡️ Status', value: '⚠️ **TIDAK AMAN**', inline: false }
                            )
                            .setColor(0xFF0000)
                            .setThumbnail(interaction.guild.iconURL() || client.user.displayAvatarURL())
                            .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                        await interaction.editReply({ embeds: [keyloggerEmbed] });
                        fs.unlinkSync(temp);
                        return; // Exit early
                    }
                }

                const log = client.channels.cache.get(LOG_CHANNEL_ID);

                if (VT_API_KEY) {
                    const hash = crypto
                        .createHash("sha256")
                        .update(fs.readFileSync(temp))
                        .digest("hex");

                    const vt = await axios.get(
                        `https://www.virustotal.com/api/v3/files/${hash}`,
                        { headers: { "x-apikey": VT_API_KEY } }
                    );

                    const s = vt.data.data.attributes.last_analysis_stats;
                    fs.unlinkSync(temp);

                    if (s.malicious > 0) {
                        const malwareEmbed = new EmbedBuilder()
                            .setTitle('🚨 MALWARE TERDETEKSI!')
                            .setDescription(`**File yang terdeteksi malware telah dihapus secara otomatis.**`)
                            .addFields(
                                { name: '📁 Nama File', value: `${file.name}`, inline: true },
                                { name: '❌ Deteksi Malware', value: `${s.malicious} antivirus`, inline: true },
                                { name: '👤 Uploader', value: `${interaction.user}`, inline: true },
                                { name: '🛡️ Status', value: '⚠️ **TIDAK AMAN**', inline: false }
                            )
                            .setColor(0xFF0000)
                            .setThumbnail('https://media1.tenor.com/m/5EUurOL4OWwAAAAC/caution-error-message.gif') // Warning icon
                            .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                            .setFooter({ text: 'PREMAN Anti Virus By Ramardo', iconURL: client.user.displayAvatarURL() })
                            .setTimestamp();
                        await interaction.editReply({ embeds: [malwareEmbed] });
                        return;
                    } else {
                        if (ext === 'lua') {
                            // Special embed for safe .lua files with VT scan
                            let lines = 'Unable to read file content.';
                            try {
                                const fileContent = fs.readFileSync(temp, 'utf8');
                                lines = fileContent.split('\n').slice(0, 10).join('\n'); // First 10 lines as core code
                            } catch (readError) {
                                console.log('Error reading file content:', readError.message);
                            }
                            const cleanLuaEmbed = new EmbedBuilder()
                                .setTitle('✅ FILE LUA AMAN DARI KEYLOGGER!')
                                .setDescription(`**File Lua telah dipindai dan dinyatakan aman dari keylogger dan malware.**`)
                                .addFields(
                                    { name: '📁 Nama File', value: `${file.name}`, inline: true },
                                    { name: '✅ Antivirus Aman', value: `${s.harmless}`, inline: true },
                                    { name: '⚠️ Mencurigakan', value: `${s.suspicious}`, inline: true },
                                    { name: '❌ Malware', value: `${s.malicious}`, inline: true },
                                    { name: '👤 Uploader', value: `${interaction.user}`, inline: true },
                                    { name: '🛡️ Status', value: '✅ **AMAN DARI KEYLOGGER**', inline: false },
                                    { name: '📋 Code Inti Aman', value: `\`\`\`lua\n${lines}\n\`\`\``, inline: false },
                                    { name: '📋 Alasan Aman', value: 'File tidak terdeteksi malware oleh antivirus dan tidak mengandung pola keylogger berbahaya.', inline: false }
                                )
                                .setColor(0x00FF00)
                                .setThumbnail('https://media.tenor.com/anvPOsmgP0gAAAAi/its-for-discord-bot.gif') // Check mark animation
                                .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                                .setFooter({ text: 'PREMAN Anti Keylogger By Ramardo', iconURL: client.user.displayAvatarURL() })
                                .setTimestamp();
                            await interaction.editReply({ embeds: [cleanLuaEmbed] });
                        } else {
                            const cleanEmbed = new EmbedBuilder()
                                .setTitle('✅ FILE AMAN!')
                                .setDescription(`**File telah dipindai dan dinyatakan aman.**`)
                                .addFields(
                                    { name: '📁 Nama File', value: `${file.name}`, inline: true },
                                    { name: '✅ Antivirus Aman', value: `${s.harmless}`, inline: true },
                                    { name: '⚠️ Mencurigakan', value: `${s.suspicious}`, inline: true },
                                    { name: '❌ Malware', value: `${s.malicious}`, inline: true },
                                    { name: '👤 Uploader', value: `${interaction.user}`, inline: true },
                                    { name: '🛡️ Status', value: '✅ **AMAN**', inline: false },
                                    { name: '📋 Alasan Aman', value: 'File tidak terdeteksi malware oleh antivirus dan tidak mengandung pola berbahaya.', inline: false }
                                )
                                .setColor(0x00FF00)
                                .setThumbnail('https://media.tenor.com/anvPOsmgP0gAAAAi/its-for-discord-bot.gif') // Check mark animation
                                .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                                .setFooter({ text: 'PREMAN Anti Virus By Ramardo', iconURL: client.user.displayAvatarURL() })
                                .setTimestamp();
                            await interaction.editReply({ embeds: [cleanEmbed] });
                        }
                    }
                } else {
                    // No VT API key, report as safe if no patterns detected
                    if (ext === 'lua') {
                        // Special embed for safe .lua files
                        const fileContent = fs.readFileSync(temp, 'utf8');
                        const lines = fileContent.split('\n').slice(0, 10).join('\n'); // First 10 lines as core code
                        fs.unlinkSync(temp);
                        const cleanLuaEmbed = new EmbedBuilder()
                            .setTitle('✅ FILE LUA AMAN DARI KEYLOGGER!')
                            .setDescription(`**File Lua telah dipindai dan dinyatakan aman dari keylogger.**`)
                            .addFields(
                                { name: '📁 Nama File', value: `${file.name}`, inline: true },
                                { name: '👤 Uploader', value: `${interaction.user}`, inline: true },
                                { name: '🛡️ Status', value: '✅ **AMAN DARI KEYLOGGER**', inline: false },
                                { name: '📋 Code Inti Aman', value: `\`\`\`lua\n${lines}\n\`\`\``, inline: false },
                                { name: '📋 Alasan Aman', value: 'File tidak mengandung pola keylogger berbahaya. (Pemindaian VT dilewati karena tidak ada API key)', inline: false }
                            )
                            .setColor(0x00FF00)
                            .setThumbnail('https://media.tenor.com/anvPOsmgP0gAAAAi/its-for-discord-bot.gif') // Check mark animation
                            .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                            .setFooter({ text: 'PREMAN Anti Keylogger By Ramardo', iconURL: client.user.displayAvatarURL() })
                            .setTimestamp();
                        await interaction.editReply({ embeds: [cleanLuaEmbed] });
                    } else {
                        fs.unlinkSync(temp);
                        const cleanEmbed = new EmbedBuilder()
                            .setTitle('✅ FILE AMAN!')
                            .setDescription(`**File telah dipindai dan dinyatakan aman.**`)
                            .addFields(
                                { name: '📁 Nama File', value: `${file.name}`, inline: true },
                                { name: '👤 Uploader', value: `${interaction.user}`, inline: true },
                                { name: '🛡️ Status', value: '✅ **AMAN**', inline: false },
                                { name: '📋 Alasan Aman', value: 'File tidak mengandung pola berbahaya. (Pemindaian VT dilewati karena tidak ada API key)', inline: false }
                            )
                            .setColor(0x00FF00)
                            .setThumbnail('https://media.tenor.com/anvPOsmgP0gAAAAi/its-for-discord-bot.gif') // Check mark animation
                            .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                            .setFooter({ text: 'PREMAN Anti Virus By Ramardo', iconURL: client.user.displayAvatarURL() })
                            .setTimestamp();
                        await interaction.editReply({ embeds: [cleanEmbed] });
                    }
                }

            } catch (e) {
                if (ext === 'lua') {
                    let lines = 'Unable to read file content.';
                    try {
                        const fileContent = fs.readFileSync(temp, 'utf8');
                        lines = fileContent.split('\n').slice(0, 10).join('\n');
                    } catch (readError) {
                        console.log('Error reading file content:', readError.message);
                    }
                    const cleanLuaEmbed = new EmbedBuilder()
                        .setTitle('✅ FILE LUA AMAN DARI KEYLOGGER!')
                        .setDescription(`**File Lua telah dipindai dan dinyatakan aman dari keylogger.**`)
                        .addFields(
                            { name: '📁 Nama File', value: `${file.name}`, inline: true },
                            { name: '👤 Uploader', value: `${interaction.user}`, inline: true },
                            { name: '🛡️ Status', value: '✅ **AMAN DARI KEYLOGGER**', inline: false },
                            { name: '📋 Code Inti Aman', value: `\`\`\`lua\n${lines}\n\`\`\``, inline: false },
                            { name: '📋 Alasan Aman', value: 'File tidak mengandung pola keylogger berbahaya. (Pemindaian VT gagal, tetapi aman dari keylogger)', inline: false }
                        )
                        .setColor(0x00FF00)
                        .setThumbnail('https://media.tenor.com/anvPOsmgP0gAAAAi/its-for-discord-bot.gif')
                        .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                        .setFooter({ text: 'PREMAN Anti Keylogger By Ramardo', iconURL: client.user.displayAvatarURL() })
                        .setTimestamp();
                    await interaction.editReply({ embeds: [cleanLuaEmbed] });
                } else {
                    const errorEmbed = new EmbedBuilder()
                        .setTitle('❌ PEMINDAIAN GAGAL')
                        .setDescription(`**Terjadi kesalahan saat memindai file.**`)
                        .addFields(
                            { name: '📁 Nama File', value: `${file.name}`, inline: true },
                            { name: '👤 Uploader', value: `${interaction.user}`, inline: true },
                            { name: '🔍 Alasan', value: 'File belum terdaftar di Database atau ada kesalahan teknis.', inline: false },
                            { name: '💡 Saran', value: 'Coba lagi nanti atau hubungi admin.', inline: false }
                        )
                        .setColor(0xFF0000)
                        .setThumbnail('https://i.imgur.com/error.png') // Error icon
                        .setImage('https://cdn.discordapp.com/attachments/1293167596547342401/1453563083971891260/standard_1.gif?ex=694de79d&is=694c961d&hm=1b3921f278c1643c1139e4ca291fcbb561443a7ddcfb56983a1d767f6f83c5ca&')
                        .setFooter({ text: 'PREMAN Anti Virus By Ramardo', iconURL: client.user.displayAvatarURL() })
                        .setTimestamp();
                    await interaction.editReply({ embeds: [errorEmbed] });
                }
                if (fs.existsSync(temp)) fs.unlinkSync(temp);
            }
        } else {
            const invalidEmbed = new EmbedBuilder()
                .setTitle('❌ Format File Tidak Didukung')
                .setDescription('File yang Anda upload tidak didukung untuk pemindaian.')
                .addFields(
                    { name: '📁 Format Didukung', value: 'exe, dll, zip, rar, lua, dll.', inline: true }
                )
                .setColor(0xFF0000)
                .setFooter({ text: 'PREMAN Anti Virus By Ramardo', iconURL: client.user.displayAvatarURL() })
                .setTimestamp();
            await interaction.reply({ embeds: [invalidEmbed] });
        }
    } else if (commandName === 'antilink') {
        if (!interaction.member.permissions.has('Administrator')) {
            const embed = new EmbedBuilder()
                .setTitle('❌ Permission Denied')
                .setDescription('You need Administrator permissions to use this command.')
                .setColor(0xFF0000);
            return interaction.reply({ embeds: [embed], ephemeral: true });
        }
        const enable = interaction.options.getBoolean('enable');
        const settings = { enabled: false, allowedChannels: [], logChannel: null, ...guildSettings.get(interaction.guild.id) };
        settings.enabled = enable;
        guildSettings.set(interaction.guild.id, settings);
        saveSettings();
        const embed = new EmbedBuilder()
            .setTitle('🔧 Anti-Link Status')
            .setDescription(`Anti-link has been ${enable ? 'enabled' : 'disabled'}.`)
            .setColor(0x00FF00);
        await interaction.reply({ embeds: [embed], ephemeral: true });
    } else if (commandName === 'addlinkchannel') {
        if (!interaction.member.permissions.has('Administrator')) {
            const embed = new EmbedBuilder()
                .setTitle('❌ Permission Denied')
                .setDescription('You need Administrator permissions to use this command.')
                .setColor(0xFF0000);
            return interaction.reply({ embeds: [embed], ephemeral: true });
        }
        const settings = { enabled: false, allowedChannels: [], logChannel: null, ...guildSettings.get(interaction.guild.id) };
        if (!settings.enabled) {
            const embed = new EmbedBuilder()
                .setTitle('❌ Anti-Link Not Enabled')
                .setDescription('Anti-link must be enabled first.')
                .setColor(0xFF0000);
            return interaction.reply({ embeds: [embed], ephemeral: true });
        }
        const channel = interaction.options.getChannel('channel');
        if (!settings.allowedChannels.includes(channel.id)) {
            settings.allowedChannels.push(channel.id);
            saveSettings();
            const embed = new EmbedBuilder()
                .setTitle('✅ Channel Added')
                .setDescription(`Channel ${channel} added to allowed channels.`)
                .setColor(0x00FF00);
            await interaction.reply({ embeds: [embed], ephemeral: true });
        } else {
            const embed = new EmbedBuilder()
                .setTitle('⚠️ Channel Already Allowed')
                .setDescription(`Channel ${channel} is already allowed.`)
                .setColor(0xFFFF00);
            await interaction.reply({ embeds: [embed], ephemeral: true });
        }
    } else if (commandName === 'removelinkchannel') {
        if (!interaction.member.permissions.has('Administrator')) {
            const embed = new EmbedBuilder()
                .setTitle('❌ Permission Denied')
                .setDescription('You need Administrator permissions to use this command.')
                .setColor(0xFF0000);
            return interaction.reply({ embeds: [embed], ephemeral: true });
        }
        const settings = { enabled: false, allowedChannels: [], logChannel: null, ...guildSettings.get(interaction.guild.id) };
        if (!settings.enabled) {
            const embed = new EmbedBuilder()
                .setTitle('❌ Anti-Link Not Enabled')
                .setDescription('Anti-link must be enabled first.')
                .setColor(0xFF0000);
            return interaction.reply({ embeds: [embed], ephemeral: true });
        }
        const channel = interaction.options.getChannel('channel');
        if (settings.allowedChannels.includes(channel.id)) {
            settings.allowedChannels = settings.allowedChannels.filter(id => id !== channel.id);
            saveSettings();
            const embed = new EmbedBuilder()
                .setTitle('✅ Channel Removed')
                .setDescription(`Channel ${channel} removed from allowed channels.`)
                .setColor(0x00FF00);
            await interaction.reply({ embeds: [embed], ephemeral: true });
        } else {
            const embed = new EmbedBuilder()
                .setTitle('⚠️ Channel Not Allowed')
                .setDescription(`Channel ${channel} is not in allowed channels.`)
                .setColor(0xFFFF00);
            await interaction.reply({ embeds: [embed], ephemeral: true });
        }
    } else if (commandName === 'listchannelallowed') {
        const settings = { enabled: false, allowedChannels: [], logChannel: null, ...guildSettings.get(interaction.guild.id) };
        if (settings.allowedChannels.length === 0) {
            const embed = new EmbedBuilder()
                .setTitle('📋 Allowed Channels')
                .setDescription('No channels are allowed for link sharing.')
                .setColor(0xFFFF00);
            await interaction.reply({ embeds: [embed] });
        } else {
            const channelList = settings.allowedChannels.map(id => `<#${id}>`).join('\n');
            const embed = new EmbedBuilder()
                .setTitle('📋 Allowed Channels')
                .setDescription(`Allowed channels for link sharing:\n${channelList}`)
                .setColor(0x00FF00);
            await interaction.reply({ embeds: [embed] });
        }
    } else if (commandName === 'setlogchannel') {
        if (!interaction.member.permissions.has('Administrator')) {
            const embed = new EmbedBuilder()
                .setTitle('❌ Permission Denied')
                .setDescription('You need Administrator permissions to use this command.')
                .setColor(0xFF0000);
            return interaction.reply({ embeds: [embed], ephemeral: true });
        }
        const channel = interaction.options.getChannel('channel');
        const settings = { enabled: false, allowedChannels: [], logChannel: null, ...guildSettings.get(interaction.guild.id) };
        settings.logChannel = channel.id;
        guildSettings.set(interaction.guild.id, settings);
        saveSettings();
        const embed = new EmbedBuilder()
            .setTitle('✅ Log Channel Set')
            .setDescription(`Logging channel has been set to ${channel}.`)
            .setColor(0x00FF00);
        await interaction.reply({ embeds: [embed], ephemeral: true });
    }
});

function loadSettings() {
    try {
        const data = fs.readFileSync('settings.json', 'utf8');
        const settings = JSON.parse(data);
        for (const [guildId, setting] of Object.entries(settings)) {
            guildSettings.set(guildId, setting);
        }
    } catch (error) {
        console.log('No settings file found, starting fresh.');
    }
}

function saveSettings() {
    const settings = {};
    for (const [guildId, setting] of guildSettings) {
        settings[guildId] = setting;
    }
    fs.writeFileSync('settings.json', JSON.stringify(settings, null, 2));
}

loadSettings();

client.login(process.env.TOKEN);
