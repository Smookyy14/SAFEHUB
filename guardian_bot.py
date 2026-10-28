"""
Guardian: an anti-nuke / anti-raid Discord bot (discord.py 2.4+)

Protects against:
  - Nukes: mass channel/role deletion, mass bans/kicks, webhook spam, rogue bot adds
  - Raids: sudden join floods (auto-lockdown + cleanup of fresh accounts)
  - Mention spam (@everyone / mass-ping floods)

Setup: see .env.example, then `python guardian_bot.py`
"""

import logging
import os
import time
from collections import defaultdict, deque
from datetime import timedelta

import discord
from discord import app_commands
from dotenv import load_dotenv

load_dotenv()

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
TOKEN = os.environ["DISCORD_TOKEN"]
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID", "0"))
WHITELIST = {int(x) for x in os.getenv("WHITELIST_IDS", "").split(",") if x.strip()}

# What to do to someone who trips anti-nuke: "strip" (remove dangerous roles),
# "kick", or "ban". Bots are always kicked/banned since managed roles can't be stripped.
PUNISHMENT = os.getenv("PUNISHMENT", "strip").lower()

# Anti-nuke: max actions per user inside WINDOW seconds before they're punished.
NUKE_WINDOW = 10
NUKE_LIMITS = {
    discord.AuditLogAction.channel_delete: 3,
    discord.AuditLogAction.channel_create: 6,
    discord.AuditLogAction.role_delete: 3,
    discord.AuditLogAction.role_create: 6,
    discord.AuditLogAction.ban: 4,
    discord.AuditLogAction.kick: 4,
    discord.AuditLogAction.webhook_create: 2,
    discord.AuditLogAction.emoji_delete: 5,
}

# Anti-raid
RAID_JOIN_LIMIT = 8            # joins...
RAID_WINDOW = 10               # ...within this many seconds triggers lockdown
RAID_KICK_ACCOUNT_DAYS = 14    # on trigger, kick recent joiners with accounts younger than this
LOCKDOWN_MIN_ACCOUNT_DAYS = 7  # while locked down, kick joiners younger than this

# Mention spam
MENTION_LIMIT = 6              # mentions in one message
MENTION_TIMEOUT_MIN = 10

DANGEROUS = (
    "administrator", "manage_guild", "manage_roles", "manage_channels",
    "manage_webhooks", "ban_members", "kick_members", "mention_everyone",
)

# --------------------------------------------------------------------------- #
# Setup
# --------------------------------------------------------------------------- #
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("guardian")

intents = discord.Intents.default()
intents.members = True      # privileged: enable in the Developer Portal
intents.moderation = True   # needed for audit log events

bot = discord.Client(intents=intents)
tree = app_commands.CommandTree(bot)

action_log: dict[tuple, deque] = defaultdict(deque)   # (guild, user, action) -> timestamps
recent_joins: dict[int, deque] = defaultdict(deque)   # guild -> (timestamp, member_id)
locked: dict[int, discord.VerificationLevel] = {}     # guild -> previous verification level


def is_trusted(guild: discord.Guild, user_id: int) -> bool:
    return user_id == bot.user.id or user_id == guild.owner_id or user_id in WHITELIST


def is_dangerous(perms: discord.Permissions) -> bool:
    return any(getattr(perms, p) for p in DANGEROUS)


async def alert(guild: discord.Guild, title: str, description: str, color=discord.Color.red()):
    log.warning("%s | %s", title, description)
    channel = guild.get_channel(LOG_CHANNEL_ID) if LOG_CHANNEL_ID else None
    if channel:
        try:
            await channel.send(embed=discord.Embed(title=title, description=description, color=color))
        except discord.HTTPException:
            pass


async def punish(guild: discord.Guild, user_id: int, reason: str) -> bool:
    if is_trusted(guild, user_id):
        return False
    member = guild.get_member(user_id)
    if member is None:
        try:
            member = await guild.fetch_member(user_id)
        except discord.HTTPException:
            return False
    try:
        if member.bot or PUNISHMENT == "kick":
            await member.kick(reason=reason)
        elif PUNISHMENT == "ban":
            await guild.ban(member, reason=reason, delete_message_seconds=0)
        else:
            safe = [r for r in member.roles
                    if r.is_default() or r.managed or not is_dangerous(r.permissions)]
            await member.edit(roles=safe, reason=reason)
        return True
    except discord.HTTPException as e:
        await alert(guild, "Punishment failed",
                    f"Could not punish <@{user_id}>: `{e}`\n"
                    "Make sure my role is **above** theirs and I have Manage Roles/Kick/Ban.")
        return False


# --------------------------------------------------------------------------- #
# Lockdown
# --------------------------------------------------------------------------- #
async def start_lockdown(guild: discord.Guild, reason: str):
    if guild.id in locked:
        return
    locked[guild.id] = guild.verification_level
    try:
        await guild.edit(verification_level=discord.VerificationLevel.highest, reason=reason)
    except discord.HTTPException:
        pass
    try:  # pauses invites; requires a recent discord.py
        await guild.edit(invites_disabled=True, reason=reason)
    except (TypeError, discord.HTTPException):
        pass
    await alert(guild, "🔒 Lockdown enabled", reason)


async def end_lockdown(guild: discord.Guild, reason: str = "Lockdown lifted"):
    previous = locked.pop(guild.id, None)
    try:
        await guild.edit(verification_level=previous or discord.VerificationLevel.medium, reason=reason)
    except discord.HTTPException:
        pass
    try:
        await guild.edit(invites_disabled=False, reason=reason)
    except (TypeError, discord.HTTPException):
        pass
    await alert(guild, "🔓 Lockdown lifted", reason, discord.Color.green())


# --------------------------------------------------------------------------- #
# Anti-nuke (audit log watcher)
# --------------------------------------------------------------------------- #
@bot.event
async def on_audit_log_entry_create(entry: discord.AuditLogEntry):
    guild = entry.guild
    uid = entry.user_id
    if uid is None or is_trusted(guild, uid):
        return

    # A non-whitelisted user adding a bot is treated as an attack.
    if entry.action is discord.AuditLogAction.bot_add:
        target = entry.target
        await punish(guild, uid, "Guardian: added an unapproved bot")
        if target is not None and not is_trusted(guild, target.id):
            try:
                await guild.kick(discord.Object(id=target.id), reason="Guardian: unapproved bot")
            except discord.HTTPException:
                pass
        await alert(guild, "🤖 Unapproved bot added",
                    f"<@{uid}> added <@{getattr(target, 'id', 0)}>. Both were removed.")
        return

    limit = NUKE_LIMITS.get(entry.action)
    if limit is None:
        return

    now = time.monotonic()
    history = action_log[(guild.id, uid, entry.action)]
    history.append(now)
    while history and now - history[0] > NUKE_WINDOW:
        history.popleft()

    if len(history) >= limit:
        history.clear()
        done = await punish(guild, uid, f"Guardian: mass {entry.action.name}")
        await alert(guild, "🚨 Nuke attempt detected",
                    f"User: <@{uid}>\nAction: `{entry.action.name}` x{limit}+ in {NUKE_WINDOW}s\n"
                    f"Punished: **{done}** ({PUNISHMENT})")
        await start_lockdown(guild, f"Nuke attempt by <@{uid}>")


# --------------------------------------------------------------------------- #
# Anti-raid (join floods)
# --------------------------------------------------------------------------- #
@bot.event
async def on_member_join(member: discord.Member):
    guild = member.guild
    age_days = (discord.utils.utcnow() - member.created_at).days

    if guild.id in locked and age_days < LOCKDOWN_MIN_ACCOUNT_DAYS and not member.bot:
        try:
            await member.kick(reason="Guardian: new account during lockdown")
        except discord.HTTPException:
            pass
        return

    now = time.monotonic()
    joins = recent_joins[guild.id]
    joins.append((now, member.id))
    while joins and now - joins[0][0] > RAID_WINDOW:
        joins.popleft()

    if len(joins) >= RAID_JOIN_LIMIT and guild.id not in locked:
        await start_lockdown(guild, f"Join flood: {len(joins)} joins in {RAID_WINDOW}s")
        kicked = 0
        for _, mid in list(joins):
            m = guild.get_member(mid)
            if m and not is_trusted(guild, m.id) and \
                    (discord.utils.utcnow() - m.created_at).days < RAID_KICK_ACCOUNT_DAYS:
                try:
                    await m.kick(reason="Guardian: raid cleanup")
                    kicked += 1
                except discord.HTTPException:
                    pass
        joins.clear()
        await alert(guild, "🧹 Raid cleanup", f"Kicked **{kicked}** fresh accounts.")


# --------------------------------------------------------------------------- #
# Mention spam
# --------------------------------------------------------------------------- #
@bot.event
async def on_message(message: discord.Message):
    if message.guild is None or message.author.bot:
        return
    if is_trusted(message.guild, message.author.id):
        return
    if isinstance(message.author, discord.Member) and message.author.guild_permissions.administrator:
        return

    mentions = len(message.mentions) + len(message.role_mentions) + int(message.mention_everyone)
    if mentions >= MENTION_LIMIT:
        try:
            await message.delete()
            await message.author.timeout(timedelta(minutes=MENTION_TIMEOUT_MIN),
                                         reason="Guardian: mention spam")
        except (discord.HTTPException, AttributeError):
            pass
        await alert(message.guild, "📢 Mention spam",
                    f"<@{message.author.id}> sent a message with {mentions} mentions and was timed out.",
                    discord.Color.orange())


# --------------------------------------------------------------------------- #
# Slash commands
# --------------------------------------------------------------------------- #
@tree.command(name="lockdown", description="Raise verification and pause invites")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def lockdown_cmd(interaction: discord.Interaction):
    await start_lockdown(interaction.guild, f"Manual lockdown by {interaction.user}")
    await interaction.response.send_message("🔒 Lockdown enabled.", ephemeral=True)


@tree.command(name="unlock", description="Lift lockdown and restore verification level")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def unlock_cmd(interaction: discord.Interaction):
    await end_lockdown(interaction.guild, f"Lifted by {interaction.user}")
    await interaction.response.send_message("🔓 Lockdown lifted.", ephemeral=True)


@tree.command(name="status", description="Show Guardian's current protection status")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def status_cmd(interaction: discord.Interaction):
    g = interaction.guild
    me = g.me
    embed = discord.Embed(title="Guardian status", color=discord.Color.blurple())
    embed.add_field(name="Lockdown", value="ON" if g.id in locked else "off")
    embed.add_field(name="Punishment", value=PUNISHMENT)
    embed.add_field(name="Whitelisted", value=str(len(WHITELIST)))
    embed.add_field(name="My top role position", value=str(me.top_role.position))
    embed.add_field(name="Has audit log access", value=str(me.guild_permissions.view_audit_log))
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.event
async def on_ready():
    log.info("Guardian online as %s in %d server(s)", bot.user, len(bot.guilds))


async def setup():
    await tree.sync()

bot.setup_hook = setup

if __name__ == "__main__":
    bot.run(TOKEN)
