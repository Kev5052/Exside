
import discord
from discord.ext import commands, tasks
import asyncio
import json
import os
from datetime import datetime, timedelta
import re
import hashlib
from collections import defaultdict, deque
import statistics

# Configuración del bot
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
intents.guilds = True
intents.moderation = True

bot = commands.Bot(command_prefix='!sec ', intents=intents)

# Configuración de seguridad por servidor
server_configs = {}

# Sistema de ban global
global_bans = set()

# Sistemas de monitoreo avanzado
user_activity = defaultdict(
    lambda: {
        'messages': deque(maxlen=50),
        'joins': deque(maxlen=10),
        'risk_score': 0,
        'warnings': 0,
        'last_activity': None,
        'message_patterns': defaultdict(int),
        'suspicious_actions': []
    })

# Patrones sospechosos mejorados
SUSPICIOUS_PATTERNS = {
    'discord_invites':
    r'discord\.gg/[a-zA-Z0-9]+|discord\.com/invite/[a-zA-Z0-9]+',
    'suspicious_urls':
    r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
    'mass_mentions': r'@everyone|@here',
    'spam_chars': r'(.)\1{8,}',
    'suspicious_domains': r'(bit\.ly|tinyurl|t\.co|shorturl|grabify|iplogger)',
    'cryptocurrency':
    r'(bitcoin|btc|ethereum|eth|crypto|wallet|seed|private key)',
    'scam_words':
    r'(free nitro|give.*away|claim.*nitro|discord.*gift|generator)',
    'zalgo_text':
    r'[\u0300-\u036F\u1AB0-\u1AFF\u1DC0-\u1DFF\u20D0-\u20FF\uFE20-\uFE2F]',
    'invisible_chars': r'[\u200B-\u200D\u2060\uFEFF]'
}

# Palabras clave de raid bots mejoradas
RAID_KEYWORDS = [
    'raid', 'nuke', 'destroy', 'spam', 'flood', 'crash', 'lag', 'ddos',
    'massban', 'massdm', 'ghost', 'ping', 'webhook', 'selfbot', 'token'
]

# Dominios maliciosos conocidos
MALICIOUS_DOMAINS = [
    'grabify.link', 'iplogger.org', 'discordapp.io', 'steamcommunity.ru',
    'discordnitro.info', 'discord-nitro.com', 'free-nitro.com'
]


def load_config():
    """Cargar configuración desde archivo"""
    global server_configs, global_bans
    try:
        with open('security_config.json', 'r') as f:
            server_configs = json.load(f)
    except FileNotFoundError:
        server_configs = {}

    try:
        with open('global_bans.json', 'r') as f:
            global_bans = set(json.load(f))
    except FileNotFoundError:
        global_bans = set()


def save_config():
    """Guardar configuración a archivo"""
    with open('security_config.json', 'w') as f:
        json.dump(server_configs, f, indent=2)

    with open('global_bans.json', 'w') as f:
        json.dump(list(global_bans), f, indent=2)


def get_server_config(guild_id):
    """Obtener configuración del servidor"""
    guild_id = str(guild_id)
    if guild_id not in server_configs:
        server_configs[guild_id] = {
            'auto_ban': True,
            'alert_channel': None,
            'admin_role': None,
            'max_messages_per_minute': 10,
            'raid_detection': True,
            'link_filter': True,
            'mention_limit': 3,
            'risk_threshold': 75,
            'advanced_detection': True,
            'quarantine_role': None,
            'lockdown_mode': False,
            'whitelist_channels': [],
            'trusted_users': []
        }
        save_config()
    return server_configs[guild_id]


def has_admin_permissions(user):
    """Verificar si el usuario tiene permisos de administrador"""
    return user.guild_permissions.administrator


async def is_admin(ctx):
    """Verificar si el usuario es administrador (para comandos legacy)"""
    return has_admin_permissions(ctx.author)


def calculate_risk_score(user_id, guild_id):
    """Calcular puntuación de riesgo basada en actividad del usuario con análisis mejorado"""
    activity = user_activity[user_id]
    config = get_server_config(guild_id)

    risk_score = 0
    current_time = datetime.utcnow()

    # Análisis de frecuencia de mensajes mejorado
    if len(activity['messages']) > 5:
        # Ventanas de tiempo progresivas
        recent_1min = [
            msg for msg in activity['messages']
            if msg['timestamp'] > current_time - timedelta(minutes=1)
        ]
        recent_5min = [
            msg for msg in activity['messages']
            if msg['timestamp'] > current_time - timedelta(minutes=5)
        ]
        recent_15min = [
            msg for msg in activity['messages']
            if msg['timestamp'] > current_time - timedelta(minutes=15)
        ]

        # Detección de spam más inteligente
        if len(recent_1min) > 8:  # Más de 8 mensajes en 1 minuto
            risk_score += 30
        elif len(recent_5min) > config.get(
                'max_messages_per_minute',
                10) * 2:  # Doble del límite en 5 min
            risk_score += 20
        elif len(recent_15min) > config.get('max_messages_per_minute',
                                            10) * 3:  # Triple en 15 min
            risk_score += 10

    # Análisis de patrones de mensajes mejorado
    unique_messages = len(
        set(msg['content'][:100] for msg in activity['messages']
            if msg['content'] and len(msg['content']) > 3))
    total_messages = len([
        msg for msg in activity['messages']
        if msg['content'] and len(msg['content']) > 3
    ])

    if total_messages > 5:
        diversity_ratio = unique_messages / total_messages

        # Solo penalizar si hay muchos mensajes Y baja diversidad
        if total_messages > 10 and diversity_ratio < 0.2:  # Muy repetitivo
            risk_score += 25
        elif total_messages > 15 and diversity_ratio < 0.4:  # Moderadamente repetitivo
            risk_score += 15

    # Análisis de contenido sospechoso con contexto
    suspicious_count = sum(1 for msg in activity['messages']
                           if msg.get('suspicious', False))
    recent_suspicious = sum(
        1 for msg in activity['messages']
        if msg.get('suspicious', False) and msg['timestamp'] > current_time -
        timedelta(minutes=10))

    if suspicious_count > 0:
        # Penalizar más si es contenido sospechoso reciente
        if recent_suspicious > 2:
            risk_score += min(recent_suspicious * 15, 45)
        else:
            risk_score += min(suspicious_count * 8, 30)

    # Análisis de edad de cuenta mejorado
    if activity.get('account_age'):
        days_old = (current_time - activity['account_age']).days
        hours_old = (current_time -
                     activity['account_age']).total_seconds() / 3600

        # Solo penalizar cuentas muy nuevas si hay otros indicadores
        if days_old < 1 and (suspicious_count > 0 or total_messages > 10):
            risk_score += 20
        elif days_old < 7 and (suspicious_count > 1 or total_messages > 20):
            risk_score += 10
        elif hours_old < 6:  # Cuentas de menos de 6 horas
            risk_score += 15

    # Acciones sospechosas con peso temporal
    recent_suspicious_actions = [
        action for action in activity['suspicious_actions']
        if action['timestamp'] > current_time - timedelta(minutes=30)
    ]

    risk_score += len(recent_suspicious_actions) * 8
    risk_score += max(0,
                      len(activity['suspicious_actions']) -
                      3) * 3  # Penalizar historial extenso

    # Bonificación por comportamiento normal
    if total_messages > 5:
        # Reducir riesgo si hay conversación normal
        normal_messages = [
            msg for msg in activity['messages']
            if not msg.get('suspicious', False) and len(msg['content']) > 10
        ]
        if len(normal_messages
               ) > total_messages * 0.7:  # 70% mensajes normales
            risk_score = max(0, risk_score - 10)

    # Reducir riesgo para cuentas con actividad histórica consistente
    if activity.get('account_age'):
        days_old = (current_time - activity['account_age']).days
        if days_old > 30 and suspicious_count == 0:
            risk_score = max(0, risk_score - 5)

    return min(risk_score, 100)


def analyze_message_content(message):
    """Análisis avanzado del contenido del mensaje con reducción de falsos positivos"""
    content = message.content.lower()
    original_content = message.content
    analysis = {
        'suspicious': False,
        'patterns': [],
        'risk_level': 0,
        'reason': []
    }

    # Ignorar mensajes muy cortos o comandos
    if len(content.strip()) < 3 or content.startswith(('/', '!', '?', '.')):
        return analysis

    # Contexto del mensaje
    is_reply = message.reference is not None
    has_attachments = len(message.attachments) > 0

    # Verificar patrones sospechosos con contexto
    pattern_weights = {
        'discord_invites': 20,
        'suspicious_urls': 15,
        'mass_mentions': 25,
        'spam_chars': 12,
        'suspicious_domains': 30,
        'cryptocurrency': 8,  # Reducido, no siempre es malicioso
        'scam_words': 25,
        'zalgo_text': 18,
        'invisible_chars': 10
    }

    for pattern_name, pattern in SUSPICIOUS_PATTERNS.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            weight = pattern_weights.get(pattern_name, 10)

            # Reducir peso para contextos legítimos
            if pattern_name == 'suspicious_urls':
                # Permitir URLs comunes y verificar contexto
                common_safe_domains = [
                    'youtube.com', 'twitter.com', 'github.com', 'google.com',
                    'wikipedia.org'
                ]
                if any(domain in content for domain in common_safe_domains):
                    weight = max(3, weight // 3)
                elif is_reply or len(original_content) > 50:  # URL en contexto
                    weight = max(5, weight // 2)

            elif pattern_name == 'cryptocurrency':
                # Reducir si es conversación normal sobre crypto
                normal_crypto_context = [
                    'precio', 'mercado', 'noticias', 'análisis', 'trading'
                ]
                if any(word in content for word in normal_crypto_context):
                    weight = max(3, weight // 2)

            elif pattern_name == 'spam_chars':
                # Reducir para reacciones normales o énfasis
                if len(matches[0]) < 12 and (is_reply or '?' in content
                                             or '!' in content):
                    weight = max(3, weight // 2)

            analysis['patterns'].append(pattern_name)
            analysis['risk_level'] += weight
            analysis['reason'].append(f"Patrón: {pattern_name}")

    # Verificar dominios maliciosos con verificación estricta
    malicious_found = False
    for domain in MALICIOUS_DOMAINS:
        if domain in content:
            # Verificar que realmente es el dominio y no parte de otra palabra
            domain_pattern = r'\b' + re.escape(domain) + r'\b'
            if re.search(domain_pattern, content, re.IGNORECASE):
                malicious_found = True
                analysis['risk_level'] += 35
                analysis['reason'].append(
                    f"Dominio malicioso confirmado: {domain}")

    if malicious_found:
        analysis['suspicious'] = True

    # Análisis de menciones mejorado
    mentions = len(message.mentions) + len(message.role_mentions)
    config = get_server_config(message.guild.id)
    mention_limit = config.get('mention_limit', 3)

    if mentions > mention_limit:
        # Considerar contexto: longitud del mensaje y si es respuesta
        mention_penalty = (mentions - mention_limit) * 8

        if is_reply and len(original_content) > 30:
            mention_penalty //= 2  # Reducir penalización si es respuesta contextual

        analysis['risk_level'] += mention_penalty
        analysis['reason'].append(f"Menciones excesivas: {mentions}")

        if mentions > mention_limit * 2:  # Solo marcar como sospechoso si es muy excesivo
            analysis['suspicious'] = True

    # Análisis de longitud mejorado
    if len(content) > 1500:
        # Solo penalizar mensajes muy largos sin contexto
        if not (is_reply or has_attachments):
            analysis['risk_level'] += 12
            analysis['reason'].append("Mensaje excesivamente largo")
    elif len(content) > 800 and not is_reply:
        analysis['risk_level'] += 5

    # Verificar caracteres Unicode sospechosos con más precisión
    if len(content) > 10:  # Solo verificar en mensajes no muy cortos
        ascii_content = content.encode('ascii',
                                       errors='ignore').decode('ascii')
        if len(content) != len(ascii_content):
            unicode_ratio = (len(content) - len(ascii_content)) / len(content)

            # Solo penalizar si hay muchos caracteres Unicode sin contexto normal
            if unicode_ratio > 0.5 and len(ascii_content.strip()) < 5:
                analysis['suspicious'] = True
                analysis['risk_level'] += 20
                analysis['reason'].append(
                    "Exceso de caracteres Unicode sospechosos")
            elif unicode_ratio > 0.3 and not any(char.isalnum()
                                                 for char in ascii_content):
                analysis['risk_level'] += 12
                analysis['reason'].append("Caracteres Unicode sospechosos")

    # Análisis de repetición de palabras
    words = content.split()
    if len(words) > 5:
        word_count = {}
        for word in words:
            if len(word) > 3:  # Solo palabras significativas
                word_count[word] = word_count.get(word, 0) + 1

        max_repetition = max(word_count.values()) if word_count else 0
        if max_repetition > len(
                words) * 0.4:  # Más del 40% es la misma palabra
            analysis['risk_level'] += 15
            analysis['reason'].append("Repetición excesiva de palabras")

    # Marcar como sospechoso solo si supera umbral
    if analysis['risk_level'] > 20:
        analysis['suspicious'] = True

    return analysis


def detect_raid_pattern(guild_id):
    """Detectar patrones de raid con análisis adaptativo y reducción de falsos positivos"""
    current_time = datetime.utcnow()

    # Ventanas de tiempo progresivas
    threshold_2min = current_time - timedelta(minutes=2)
    threshold_5min = current_time - timedelta(minutes=5)
    threshold_15min = current_time - timedelta(minutes=15)

    # Contadores por ventana de tiempo
    stats = {
        '2min': {
            'joins': 0,
            'messages': 0,
            'high_risk': 0,
            'suspicious_messages': 0
        },
        '5min': {
            'joins': 0,
            'messages': 0,
            'high_risk': 0,
            'suspicious_messages': 0
        },
        '15min': {
            'joins': 0,
            'messages': 0,
            'high_risk': 0,
            'suspicious_messages': 0
        }
    }

    # Análisis por usuario
    coordinated_users = 0
    similar_patterns = 0

    for user_id, activity in user_activity.items():
        risk_score = calculate_risk_score(user_id, guild_id)

        # Contar actividad por ventanas
        for window, threshold in [('2min', threshold_2min),
                                  ('5min', threshold_5min),
                                  ('15min', threshold_15min)]:
            user_joins = sum(1 for join in activity['joins']
                             if join > threshold)
            user_messages = sum(1 for msg in activity['messages']
                                if msg['timestamp'] > threshold)
            user_suspicious = sum(1 for msg in activity['messages']
                                  if msg['timestamp'] > threshold
                                  and msg.get('suspicious', False))

            stats[window]['joins'] += user_joins
            stats[window]['messages'] += user_messages
            stats[window]['suspicious_messages'] += user_suspicious

            if risk_score > 70:
                stats[window]['high_risk'] += 1

        # Detectar actividad coordinada (usuarios con patrones similares)
        recent_messages = [
            msg for msg in activity['messages']
            if msg['timestamp'] > threshold_5min
        ]
        if len(recent_messages) > 3:
            # Verificar si los mensajes son muy similares entre usuarios
            message_content = [
                msg['content'][:50] for msg in recent_messages
                if msg['content']
            ]
            if len(set(message_content)
                   ) < len(message_content) * 0.3:  # 70% mensajes similares
                coordinated_users += 1

    # Obtener tamaño del servidor para umbrales adaptativos
    try:
        guild = next(guild for guild in bot.guilds if guild.id == guild_id)
        server_size = guild.member_count
    except:
        server_size = 100  # Valor por defecto

    # Umbrales adaptativos basados en tamaño del servidor
    base_join_threshold = max(3, server_size // 100)  # Al menos 3, escalable
    base_message_threshold = max(15, server_size // 20)

    # Determinar indicadores de raid con umbrales adaptativos
    raid_indicators = {
        'mass_join_critical':
        stats['2min']['joins']
        > base_join_threshold * 2,  # Uniones muy rápidas
        'mass_join_moderate':
        stats['5min']['joins'] > base_join_threshold
        and stats['2min']['joins'] > 1,
        'message_flood_critical':
        stats['2min']['messages'] > base_message_threshold,
        'message_flood_moderate':
        stats['5min']['messages'] > base_message_threshold * 2,
        'high_risk_concentration':
        stats['5min']['high_risk'] > max(2, base_join_threshold // 2),
        'coordinated_activity':
        (coordinated_users > 2 and stats['5min']['joins'] > 1)
        or (stats['5min']['suspicious_messages'] > 5
            and stats['5min']['joins'] > 0),
        'sustained_activity':
        (stats['15min']['joins'] > base_join_threshold * 2
         and stats['15min']['messages'] > base_message_threshold * 3)
    }

    # Calcular nivel de confianza del raid
    confidence_score = 0
    if raid_indicators['mass_join_critical']:
        confidence_score += 30
    if raid_indicators['message_flood_critical']:
        confidence_score += 25
    if raid_indicators['coordinated_activity']:
        confidence_score += 20
    if raid_indicators['high_risk_concentration']:
        confidence_score += 15
    if raid_indicators['sustained_activity']:
        confidence_score += 10

    # Solo reportar raid si hay suficiente confianza
    raid_indicators['confirmed_raid'] = confidence_score >= 40
    raid_indicators['confidence_score'] = confidence_score

    return raid_indicators


async def send_alert(guild, message, user=None, priority="normal"):
    """Enviar alerta al canal configurado con niveles de prioridad"""
    config = get_server_config(guild.id)
    alert_channel_id = config.get('alert_channel')

    if alert_channel_id:
        channel = guild.get_channel(alert_channel_id)
        if channel:
            color_map = {
                "low": discord.Color.yellow(),
                "normal": discord.Color.orange(),
                "high": discord.Color.red(),
                "critical": discord.Color.dark_red()
            }

            priority_emojis = {
                "low": "⚠️",
                "normal": "🚨",
                "high": "🔥",
                "critical": "💀"
            }

            embed = discord.Embed(
                title=
                f"{priority_emojis.get(priority, '🚨')} ALERTA DE SEGURIDAD - {priority.upper()}",
                description=message,
                color=color_map.get(priority, discord.Color.red()),
                timestamp=datetime.utcnow())

            if user:
                embed.add_field(name="Usuario",
                                value=f"{user.mention} ({user.id})",
                                inline=True)
                embed.add_field(name="Cuenta creada",
                                value=user.created_at.strftime("%d/%m/%Y"),
                                inline=True)

                # Añadir puntuación de riesgo
                risk_score = calculate_risk_score(user.id, guild.id)
                embed.add_field(name="Puntuación de riesgo",
                                value=f"{risk_score}/100",
                                inline=True)

            await channel.send(embed=embed)


def is_suspicious_bot(member):
    """Detectar si un bot es sospechoso con análisis mejorado y menos falsos positivos"""
    if not member.bot:
        return False, [], False

    reasons = []
    severity_score = 0
    requires_global_ban = False

    # Verificar nombre del bot con coincidencias exactas
    name_lower = member.name.lower()
    critical_keywords = ['raid', 'nuke', 'destroy', 'massban',
                         'ddos']  # Estos causan ban global
    high_risk_keywords = ['spam', 'flood']
    medium_risk_keywords = ['ghost', 'webhook', 'selfbot', 'token']

    for keyword in critical_keywords:
        if keyword in name_lower:
            reasons.append(
                f"Nombre CRÍTICO: '{keyword}' - Bot de raid detectado")
            severity_score += 5
            requires_global_ban = True

    for keyword in high_risk_keywords:
        if keyword in name_lower:
            reasons.append(f"Nombre altamente sospechoso: '{keyword}'")
            severity_score += 3

    for keyword in medium_risk_keywords:
        if keyword in name_lower:
            reasons.append(f"Nombre potencialmente sospechoso: '{keyword}'")
            severity_score += 1

    # Verificar edad de la cuenta con más precisión
    account_age = datetime.utcnow() - member.created_at.replace(tzinfo=None)
    if account_age < timedelta(hours=6):  # Muy nuevo
        reasons.append(
            f"Cuenta extremadamente nueva: {account_age.total_seconds()/3600:.1f} horas"
        )
        severity_score += 2
        # Bot muy nuevo con nombre crítico = ban global
        if any(keyword in name_lower for keyword in critical_keywords):
            requires_global_ban = True
    elif account_age < timedelta(days=2):  # Bastante nuevo
        reasons.append(
            f"Cuenta muy nueva: {account_age.total_seconds()/3600:.1f} horas")
        severity_score += 1

    # Verificar avatar por defecto solo para bots muy nuevos
    if member.avatar is None and account_age < timedelta(days=1):
        reasons.append("Sin avatar personalizado y cuenta nueva")
        severity_score += 1

    # Verificar si es bot verificado (menos sospechoso)
    if member.public_flags.verified_bot:
        severity_score = max(0, severity_score -
                             2)  # Reducir sospecha para bots verificados
        requires_global_ban = False  # Los bots verificados no se banean globalmente

    # Verificar actividad de la cuenta con criterios más estrictos
    if not member.public_flags.verified_bot and account_age < timedelta(
            hours=12) and severity_score > 0:
        reasons.append(
            "Bot no verificado, muy nuevo y con indicadores sospechosos")
        severity_score += 1

    # Solo considerar sospechoso si hay suficientes indicadores
    return severity_score >= 3, reasons, requires_global_ban


def is_suspicious_user(member):
    """Detectar si un usuario es sospechoso con análisis mejorado"""
    reasons = []
    severity_score = 0
    requires_global_ban = False

    # Verificar edad de la cuenta con umbrales más estrictos
    account_age = datetime.utcnow() - member.created_at.replace(tzinfo=None)
    hours_old = account_age.total_seconds() / 3600

    if hours_old < 2:  # Menos de 2 horas
        reasons.append(f"Cuenta extremadamente nueva: {hours_old:.1f} horas")
        severity_score += 3
    elif hours_old < 12:  # Menos de 12 horas
        reasons.append(f"Cuenta muy nueva: {hours_old:.1f} horas")
        severity_score += 2
    elif hours_old < 72:  # Menos de 3 días
        severity_score += 1

    # Verificar nombre sospechoso con coincidencias más precisas
    name_lower = member.name.lower()
    display_name_lower = member.display_name.lower(
    ) if member.display_name else ""

    critical_keywords = ['raid', 'nuke', 'destroy', 'massban',
                         'ddos']  # Estos causan ban global
    high_risk_keywords = ['spam', 'flood']

    for keyword in critical_keywords:
        if keyword in name_lower or keyword in display_name_lower:
            reasons.append(
                f"Nombre CRÍTICO: contiene '{keyword}' - Posible raider")
            severity_score += 5
            requires_global_ban = True

    for keyword in high_risk_keywords:
        if keyword in name_lower or keyword in display_name_lower:
            reasons.append(
                f"Nombre altamente sospechoso: contiene '{keyword}'")
            severity_score += 3

    # Verificar patrones en el nombre más inteligentemente
    unique_chars = len(set(member.name.lower()))
    name_length = len(member.name)

    if name_length > 5 and unique_chars < 3:  # Muy pocos caracteres únicos en nombre largo
        reasons.append("Nombre con patrones muy repetitivos")
        severity_score += 2
    elif name_length > 10 and unique_chars < 5:  # Pocas variaciones en nombre muy largo
        severity_score += 1

    # Verificar nombres que son solo números o caracteres aleatorios
    if re.match(r'^[0-9]+$', member.name):  # Solo números
        reasons.append("Nombre compuesto solo de números")
        severity_score += 2
    elif re.match(r'^[a-zA-Z0-9]{10,}$',
                  member.name) and unique_chars < name_length * 0.4:
        reasons.append("Nombre aparenta ser aleatorio")
        severity_score += 1

    # Verificar avatar por defecto solo para cuentas muy nuevas
    if member.avatar is None and hours_old < 6:
        reasons.append("Sin avatar personalizado y cuenta muy nueva")
        severity_score += 2
    elif member.avatar is None and hours_old < 24:
        severity_score += 1

    # Verificar combinación de factores peligrosos para ban global
    if hours_old < 1 and member.avatar is None and severity_score >= 2:
        reasons.append(
            "Combinación crítica: cuenta nueva, sin avatar y nombre sospechoso"
        )
        severity_score += 2

        # Si tiene nombre crítico y es muy nuevo, ban global
        if any(keyword in name_lower or keyword in display_name_lower
               for keyword in critical_keywords):
            requires_global_ban = True

    # Solo considerar sospechoso si hay suficientes indicadores
    return severity_score >= 4, reasons, requires_global_ban


async def quarantine_user(member, reason="Actividad sospechosa"):
    """Poner usuario en cuarentena"""
    config = get_server_config(member.guild.id)
    quarantine_role_id = config.get('quarantine_role')

    if quarantine_role_id:
        quarantine_role = member.guild.get_role(quarantine_role_id)
        if quarantine_role:
            try:
                await member.add_roles(quarantine_role, reason=reason)
                return True
            except discord.Forbidden:
                pass

    return False


async def send_ban_notification(user,
                                is_global=False,
                                guild_name=None,
                                reason=None):
    """Enviar notificación de ban al usuario"""
    try:
        embed = discord.Embed(title="🚫 Has sido baneado",
                              color=discord.Color.red(),
                              timestamp=datetime.utcnow())

        if is_global:
            embed.description = f"**Has recibido un ban global por actividad extremadamente peligrosa.**"
            embed.add_field(
                name="📋 Detalles:",
                value=
                f"• **Tipo**: Ban Global\n• **Razón**: {reason or 'Actividad maliciosa detectada'}\n• **Alcance**: Todos los servidores con Exside",
                inline=False)
        else:
            embed.description = f"**Has sido baneado del servidor: {guild_name}**"
            embed.add_field(
                name="📋 Detalles:",
                value=
                f"• **Servidor**: {guild_name}\n• **Razón**: {reason or 'Violación de las normas de seguridad'}",
                inline=False)

        embed.add_field(
            name="⚖️ ¿Crees que es un error?",
            value=
            "Si consideras que este ban fue aplicado incorrectamente, puedes apelar la sanción en nuestro servidor de soporte:",
            inline=False)

        embed.add_field(name="🔗 Servidor de Soporte",
                        value="https://discord.gg/4JFmFxZEyR",
                        inline=False)

        embed.add_field(
            name="ℹ️ Información Adicional",
            value=
            "• Nuestro equipo revisará tu apelación en un plazo de 24-48 horas\n• Proporciona toda la información relevante en tu apelación\n• Los bans por actividad maliciosa son tomados muy en serio",
            inline=False)

        await user.send(embed=embed)

    except discord.Forbidden:
        # El usuario tiene los DMs cerrados
        pass
    except Exception as e:
        print(f"Error enviando notificación de ban a {user.id}: {e}")


async def global_ban_user(user_id, reason="Actividad maliciosa extrema"):
    """Banear usuario globalmente de todos los servidores"""
    global global_bans

    # Agregar a la lista de bans globales
    global_bans.add(user_id)
    save_config()

    banned_guilds = []
    failed_guilds = []

    # Banear de todos los servidores donde esté el bot
    for guild in bot.guilds:
        try:
            # Verificar si el usuario está en el servidor
            member = guild.get_member(user_id)
            if member:
                await member.ban(reason=f"BAN GLOBAL: {reason}")
                banned_guilds.append(guild.name)

                # Enviar notificación por DM
                await send_ban_notification(member,
                                            is_global=True,
                                            reason=reason)

                # Enviar alerta al canal del servidor
                await send_alert(
                    guild,
                    f"🚫 **BAN GLOBAL APLICADO**\n**Usuario**: {member.mention} ({member.id})\n**Razón**: {reason}\n**Acción**: Usuario baneado automáticamente por detección global",
                    member,
                    priority="critical")
            else:
                # El usuario no está en este servidor, pero lo agregamos a la lista de bans por si se une
                try:
                    user = await bot.fetch_user(user_id)
                    await guild.ban(user,
                                    reason=f"BAN GLOBAL PREVENTIVO: {reason}")
                    banned_guilds.append(f"{guild.name} (preventivo)")
                except:
                    failed_guilds.append(guild.name)

        except discord.Forbidden:
            failed_guilds.append(guild.name)
        except Exception as e:
            print(f"Error baneando globalmente en {guild.name}: {e}")
            failed_guilds.append(guild.name)

    print(f"🚫 Ban global aplicado a usuario {user_id}")
    print(
        f"✅ Baneado en: {', '.join(banned_guilds) if banned_guilds else 'Ningún servidor'}"
    )
    if failed_guilds:
        print(f"❌ Falló en: {', '.join(failed_guilds)}")

    return len(banned_guilds), len(failed_guilds)


async def check_global_ban_on_join(member):
    """Verificar si un usuario tiene ban global al unirse a un servidor"""
    if member.id in global_bans:
        try:
            await member.ban(
                reason="Usuario con ban global - aplicación automática")

            await send_alert(
                member.guild,
                f"🚫 **BAN GLOBAL DETECTADO**\n**Usuario**: {member.mention} ({member.id})\n**Acción**: Usuario baneado automáticamente por ban global existente",
                member,
                priority="high")

            # Enviar notificación al usuario
            await send_ban_notification(member,
                                        is_global=True,
                                        reason="Ban global existente")

            return True

        except discord.Forbidden:
            await send_alert(
                member.guild,
                f"⚠️ **USUARIO CON BAN GLOBAL DETECTADO**\n**Usuario**: {member.mention} ({member.id})\n**Error**: No pude banear automáticamente - verificar permisos",
                member,
                priority="critical")
        except Exception as e:
            print(
                f"Error aplicando ban global a {member.id} en {member.guild.name}: {e}"
            )

    return False


async def create_automatic_panel():
    """Crear panel automático SOLO en el servidor específico autorizado"""
    target_guild_id = 1391384362381217812

    # Buscar el servidor específico AUTORIZADO
    target_guild = None
    for guild in bot.guilds:
        if guild.id == target_guild_id:
            target_guild = guild
            break

    if not target_guild:
        print(
            f"❌ Servidor autorizado para panel no encontrado: {target_guild_id}"
        )
        return

    # Buscar un canal adecuado para enviar el panel
    target_channel = None

    # Primero buscar canal de alertas configurado
    config = get_server_config(target_guild.id)
    if config.get('alert_channel'):
        target_channel = target_guild.get_channel(config['alert_channel'])

    # Si no hay canal de alertas, buscar uno apropiado
    if not target_channel:
        # Buscar canales con nombres relacionados
        for channel in target_guild.text_channels:
            if any(name in channel.name.lower()
                   for name in ['admin', 'staff', 'mod', 'seg', 'security']):
                if channel.permissions_for(target_guild.me).send_messages:
                    target_channel = channel
                    break

        # Si no encuentra, usar el primer canal donde pueda escribir
        if not target_channel:
            for channel in target_guild.text_channels:
                if channel.permissions_for(target_guild.me).send_messages:
                    target_channel = channel
                    break

    if not target_channel:
        print(f"❌ No se encontró un canal apropiado en {target_guild.name}")
        return

    try:
        # Crear embed del panel
        embed = discord.Embed(
            title="🔓 Panel de Gestión de Bans Globales",
            description="Sistema seguro para remover bans globales de usuarios",
            color=discord.Color.orange(),
            timestamp=datetime.utcnow())

        embed.add_field(name="📋 Información",
                        value=f"""
            • **Bans globales activos**: {len(global_bans)}
            • **Servidor autorizado**: ✅ Verificado
            • **Permisos**: Solo administradores
            """,
                        inline=False)

        embed.add_field(name="🔧 Instrucciones",
                        value="""
            1. Haz clic en el botón "🔓 Remover Ban Global"
            2. Ingresa el ID del usuario
            3. Proporciona una razón para el unban
            4. Confirma la acción
            """,
                        inline=False)

        embed.add_field(
            name="⚠️ Importante",
            value=
            "• El usuario debe ser desbaneado manualmente de cada servidor\n• Esta acción se registra en los logs de seguridad\n• Solo usar en casos justificados",
            inline=False)

        embed.set_footer(
            text="Sistema de Seguridad Exside - Panel Automático",
            icon_url=bot.user.avatar.url if bot.user.avatar else None)

        # Crear vista con botón persistente
        view = UnbanGlobalView()

        # Enviar el panel
        await target_channel.send(
            "🛡️ **Panel de Control Activado** - Sistema de gestión de bans globales disponible",
            embed=embed,
            view=view)

        print(
            f"✅ Panel automático creado en {target_guild.name} - #{target_channel.name}"
        )

    except Exception as e:
        print(f"❌ Error creando panel automático: {e}")


async def setup_server_roles(guild):
    """Crear roles necesarios para el bot en un servidor"""
    try:
        # Verificar si el bot tiene permisos para crear roles
        if not guild.me.guild_permissions.manage_roles:
            print(f"❌ Sin permisos para crear roles en {guild.name}")
            return

        # Crear rol de cuarentena
        quarantine_role_name = "🔒 Cuarentena - Exside"
        quarantine_role = discord.utils.get(guild.roles,
                                            name=quarantine_role_name)

        if not quarantine_role:
            # Permisos muy limitados para cuarentena
            quarantine_permissions = discord.Permissions(
                read_messages=True,
                send_messages=False,
                add_reactions=False,
                connect=False,
                speak=False,
                create_instant_invite=False,
                change_nickname=False)

            quarantine_role = await guild.create_role(
                name=quarantine_role_name,
                permissions=quarantine_permissions,
                color=discord.Color.dark_grey(),
                hoist=False,
                mentionable=False,
                reason="Rol de cuarentena para usuarios sospechosos")
            print(
                f"✅ Rol de cuarentena creado: {quarantine_role_name} en {guild.name}"
            )

            # Configurar automáticamente el rol de cuarentena
            config = get_server_config(guild.id)
            config['quarantine_role'] = quarantine_role.id
            save_config()

        return True

    except discord.Forbidden:
        print(
            f"❌ Sin permisos suficientes para configurar roles en {guild.name}"
        )
        return False
    except Exception as e:
        print(f"❌ Error creando roles en {guild.name}: {e}")
        return False


@bot.event
async def on_guild_join(guild):
    """Evento cuando el bot se une a un servidor nuevo"""
    print(f"🎯 Bot unido a nuevo servidor: {guild.name} (ID: {guild.id})")

    # Configurar roles automáticamente
    await setup_server_roles(guild)

    # Crear canal de alertas por defecto si es posible
    try:
        if guild.me.guild_permissions.manage_channels:
            # Buscar canal existente o crear uno nuevo
            alert_channel = discord.utils.get(guild.text_channels,
                                              name="exside-alertas")

            if not alert_channel:
                overwrites = {
                    guild.default_role:
                    discord.PermissionOverwrite(send_messages=False),
                    guild.me:
                    discord.PermissionOverwrite(send_messages=True,
                                                read_messages=True)
                }

                alert_channel = await guild.create_text_channel(
                    "exside-alertas",
                    overwrites=overwrites,
                    topic="🛡️ Canal de alertas de seguridad de Exside",
                    reason="Canal automático para alertas de seguridad")

                # Configurar automáticamente como canal de alertas
                config = get_server_config(guild.id)
                config['alert_channel'] = alert_channel.id
                save_config()

                print(
                    f"✅ Canal de alertas creado: #{alert_channel.name} en {guild.name}"
                )

                # Enviar mensaje de bienvenida
                embed = discord.Embed(
                    title="🛡️ ¡Exside se ha unido al servidor!",
                    description=
                    "Sistema de seguridad avanzado ahora protegiendo este servidor",
                    color=discord.Color.green())

                embed.add_field(name="✅ Configuración Automática Completada:",
                                value=f"""
                    • Rol de cuarentena: `🔒 Cuarentena - Exside`
                    • Canal de alertas: {alert_channel.mention}
                    """,
                                inline=False)

                embed.add_field(
                    name="🔧 Configuración Adicional:",
                    value=
                    "Usa `/configurar` para ver todas las opciones disponibles\n**Nota**: Panel de unban global solo disponible en servidor autorizado",
                    inline=False)

                await alert_channel.send(embed=embed)

    except discord.Forbidden:
        print(f"❌ Sin permisos para crear canal de alertas en {guild.name}")
    except Exception as e:
        print(f"❌ Error creando canal de alertas en {guild.name}: {e}")


@bot.event
async def on_ready():
    print(f'🛡️ Bot de seguridad {bot.user} conectado!')
    print(f'Protegiendo {len(bot.guilds)} servidores')
    load_config()

    # Configurar roles en servidores existentes
    for guild in bot.guilds:
        await setup_server_roles(guild)

    # Crear panel automático en el servidor específico
    await create_automatic_panel()

    # Iniciar tareas de monitoreo
    if not monitor_activity.is_running():
        monitor_activity.start()

    # Sincronizar comandos slash
    try:
        synced = await bot.tree.sync()
        print(f'Sincronizados {len(synced)} comandos slash')
    except Exception as e:
        print(f'Error sincronizando comandos: {e}')


@tasks.loop(minutes=5)
async def monitor_activity():
    """Monitorear actividad y detectar patrones sospechosos"""
    current_time = datetime.utcnow()

    for guild in bot.guilds:
        config = get_server_config(guild.id)

        if not config.get('advanced_detection', True):
            continue

        # Detectar patrones de raid con nuevo sistema
        raid_indicators = detect_raid_pattern(guild.id)

        if raid_indicators.get('confirmed_raid', False):
            confidence = raid_indicators.get('confidence_score', 0)
            active_indicators = [
                k for k, v in raid_indicators.items()
                if v and k not in ['confirmed_raid', 'confidence_score']
            ]

            priority = "critical" if confidence > 60 else "high"
            alert_message = f"🚨 **RAID DETECTADO** (Confianza: {confidence}%)\n"
            alert_message += f"**Indicadores**: {', '.join(active_indicators)}"

            await send_alert(guild, alert_message, priority=priority)

        elif any(
                raid_indicators.get(k, False)
                for k in ['mass_join_moderate', 'message_flood_moderate']):
            # Alerta de menor prioridad para actividad sospechosa pero no confirmada
            alert_message = "⚠️ **Actividad sospechosa detectada**\n"
            alert_message += "Monitoreando posibles patrones de raid..."

            await send_alert(guild, alert_message, priority="normal")

    # Limpiar datos antiguos
    for user_id in list(user_activity.keys()):
        activity = user_activity[user_id]
        # Eliminar mensajes antiguos
        activity['messages'] = deque([
            msg for msg in activity['messages']
            if msg['timestamp'] > current_time - timedelta(hours=24)
        ],
                                     maxlen=50)
        # Eliminar uniones antiguas
        activity['joins'] = deque([
            join for join in activity['joins']
            if join > current_time - timedelta(hours=24)
        ],
                                  maxlen=10)


@bot.event
async def on_member_join(member):
    """Detectar y manejar miembros sospechosos con análisis mejorado"""
    config = get_server_config(member.guild.id)

    # Verificar ban global primero
    if await check_global_ban_on_join(member):
        return  # Usuario ya baneado globalmente

    if not config.get('raid_detection', True):
        return

    # Registrar unión
    user_activity[member.id]['joins'].append(datetime.utcnow())
    user_activity[member.id]['account_age'] = member.created_at.replace(
        tzinfo=None)

    # Analizar bot sospechoso
    if member.bot:
        is_suspicious, reasons, requires_global_ban = is_suspicious_bot(member)
        if is_suspicious:
            try:
                if requires_global_ban:
                    # Ban global para bots extremadamente peligrosos
                    await global_ban_user(
                        member.id,
                        f"Bot de raid crítico: {', '.join(reasons)}")
                else:
                    # Ban local normal
                    await member.ban(
                        reason=f"Bot sospechoso: {', '.join(reasons)}")

                    # Enviar notificación al usuario
                    await send_ban_notification(
                        member,
                        is_global=False,
                        guild_name=member.guild.name,
                        reason=f"Bot sospechoso: {', '.join(reasons)}")

                    await send_alert(
                        member.guild,
                        f"🚫 **Bot sospechoso baneado**: {member.name}\n**Razones**: {', '.join(reasons)}",
                        member,
                        priority="high")
            except discord.Forbidden:
                await send_alert(
                    member.guild,
                    f"⚠️ **Bot sospechoso detectado pero no pude banearlo**: {member.name}\n**Razones**: {', '.join(reasons)}",
                    member,
                    priority="normal")

    # Analizar usuario sospechoso
    else:
        is_suspicious, reasons, requires_global_ban = is_suspicious_user(
            member)
        if is_suspicious:
            risk_score = calculate_risk_score(member.id, member.guild.id)
            user_activity[member.id]['risk_score'] = risk_score

            if requires_global_ban:
                # Ban global para usuarios extremadamente peligrosos
                await global_ban_user(
                    member.id, f"Usuario crítico: {', '.join(reasons)}")

            elif risk_score > config.get('risk_threshold', 75):
                # Ban local para alto riesgo
                try:
                    await member.ban(
                        reason=f"Alto riesgo: {', '.join(reasons)}")

                    # Enviar notificación al usuario
                    await send_ban_notification(
                        member,
                        is_global=False,
                        guild_name=member.guild.name,
                        reason=f"Alto riesgo: {', '.join(reasons)}")

                    await send_alert(
                        member.guild,
                        f"🚫 **Usuario de alto riesgo baneado**: {member.name}\n**Razones**: {', '.join(reasons)}\n**Riesgo**: {risk_score}/100",
                        member,
                        priority="high")
                except discord.Forbidden:
                    # Intentar cuarentena si no se puede banear
                    quarantined = await quarantine_user(
                        member, f"Alto riesgo: {', '.join(reasons)}")

                    if quarantined:
                        await send_alert(
                            member.guild,
                            f"🔒 **Usuario en cuarentena**: {member.name}\n**Razones**: {', '.join(reasons)}\n**Riesgo**: {risk_score}/100",
                            member,
                            priority="normal")
                    else:
                        await send_alert(
                            member.guild,
                            f"⚠️ **Usuario sospechoso detectado**: {member.name}\n**Razones**: {', '.join(reasons)}\n**Riesgo**: {risk_score}/100",
                            member,
                            priority="normal")
            else:
                # Solo cuarentena para riesgo moderado
                quarantined = await quarantine_user(
                    member, f"Riesgo moderado: {', '.join(reasons)}")

                if quarantined:
                    await send_alert(
                        member.guild,
                        f"🔒 **Usuario en cuarentena**: {member.name}\n**Razones**: {', '.join(reasons)}\n**Riesgo**: {risk_score}/100",
                        member,
                        priority="normal")
                else:
                    await send_alert(
                        member.guild,
                        f"⚠️ **Usuario sospechoso detectado**: {member.name}\n**Razones**: {', '.join(reasons)}\n**Riesgo**: {risk_score}/100",
                        member,
                        priority="normal")


@bot.event
async def on_message(message):
    """Monitorear mensajes con análisis avanzado"""
    if message.author.bot and message.author != bot.user:
        return

    if not message.guild:
        return

    config = get_server_config(message.guild.id)

    # Registrar actividad del mensaje
    user_activity[message.author.id]['messages'].append({
        'content':
        message.content,
        'timestamp':
        datetime.utcnow(),
        'channel':
        message.channel.id,
        'suspicious':
        False
    })
    user_activity[message.author.id]['last_activity'] = datetime.utcnow()

    # Análisis de contenido
    analysis = analyze_message_content(message)

    if analysis['suspicious']:
        user_activity[message.author.id]['messages'][-1]['suspicious'] = True
        user_activity[message.author.id]['suspicious_actions'].append({
            'type':
            'suspicious_message',
            'timestamp':
            datetime.utcnow(),
            'details':
            analysis['reason']
        })

        # Calcular riesgo actualizado
        risk_score = calculate_risk_score(message.author.id, message.guild.id)
        user_activity[message.author.id]['risk_score'] = risk_score

        # Tomar acción según el riesgo con umbrales más inteligentes
        threshold = config.get('risk_threshold', 75)

        if risk_score > threshold and analysis[
                'risk_level'] > 25:  # Doble verificación
            try:
                await message.delete()

                # Enviar alerta de alto riesgo
                await send_alert(
                    message.guild,
                    f"🗑️ **Mensaje sospechoso eliminado**\n**Usuario**: {message.author.mention}\n**Razones**: {', '.join(analysis['reason'])}\n**Riesgo**: {risk_score}/100",
                    message.author,
                    priority="high")

                # Considerar cuarentena solo con alto riesgo confirmado
                if risk_score > 90 and analysis['risk_level'] > 30:
                    await quarantine_user(message.author,
                                          f"Riesgo crítico: {risk_score}/100")

            except discord.Forbidden:
                await send_alert(
                    message.guild,
                    f"⚠️ **Mensaje sospechoso detectado (no pude eliminarlo)**\n**Usuario**: {message.author.mention}\n**Razones**: {', '.join(analysis['reason'])}\n**Riesgo**: {risk_score}/100",
                    message.author,
                    priority="normal")

        elif config.get(
                'link_filter',
                True) and analysis['risk_level'] > 25:  # Umbral más alto
            # Solo eliminar si hay alta confianza de que es malicioso
            malicious_indicators = [
                'dominio malicioso', 'scam_words', 'suspicious_domains'
            ]
            has_high_confidence = any(indicator in ' '.join(analysis['reason'])
                                      for indicator in malicious_indicators)

            if has_high_confidence:
                try:
                    await message.delete()
                    await send_alert(
                        message.guild,
                        f"🗑️ **Mensaje con contenido malicioso eliminado**\n**Usuario**: {message.author.mention}\n**Razones**: {', '.join(analysis['reason'])}",
                        message.author,
                        priority="normal")
                except discord.Forbidden:
                    pass
            else:
                # Solo alertar sin eliminar para contenido dudoso
                if analysis['risk_level'] > 20:
                    await send_alert(
                        message.guild,
                        f"⚠️ **Contenido potencialmente sospechoso detectado**\n**Usuario**: {message.author.mention}\n**Razones**: {', '.join(analysis['reason'])}\n**Nivel**: {analysis['risk_level']}",
                        message.author,
                        priority="low")

    await bot.process_commands(message)


# Comandos de configuración mejorados
@bot.tree.command(name="configurar",
                  description="Configurar el sistema de seguridad avanzado")
async def configurar(interaction: discord.Interaction):
    if not has_admin_permissions(interaction.user):
        await interaction.response.send_message(
            "❌ Solo usuarios con permisos de administrador pueden usar este comando.",
            ephemeral=True)
        return

    embed = discord.Embed(
        title="🛡️ Panel de Configuración de Seguridad Avanzado",
        description="Configura los sistemas de seguridad de **Exside**:",
        color=discord.Color.blue())

    embed.add_field(name="📊 Configuración Básica:",
                    value="""
        `/canal_alertas <canal>` - Canal de alertas de seguridad (disponible para todos)
        `/auto_ban <on/off>` - Auto-ban de usuarios sospechosos
        `/limite_menciones <número>` - Límite de menciones por mensaje
        `/umbral_riesgo <número>` - Umbral de riesgo (0-100)
        """,
                    inline=False)

    embed.add_field(name="🔍 Detección Avanzada:",
                    value="""
        `/deteccion_avanzada <on/off>` - Análisis de comportamiento
        `/deteccion_raids <on/off>` - Detección de patrones de raid
        `/filtro_links <on/off>` - Filtro de enlaces maliciosos
        `/cuarentena_rol <rol>` - Rol de cuarentena
        """,
                    inline=False)

    embed.add_field(name="📋 Gestión:",
                    value="""
        `/estado` - Ver configuración actual
        `/estadisticas` - Estadísticas de seguridad
        `/lista_riesgo` - Usuarios de alto riesgo
        `/ban_manual <usuario>` - Ban manual del servidor
        `/lista_bans_globales` - Ver bans globales activos
        
        **Panel Unban**: Solo disponible en servidor autorizado
        """,
                    inline=False)

    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(
    name="umbral_riesgo",
    description="Configurar umbral de riesgo para acciones automáticas")
async def umbral_riesgo(interaction: discord.Interaction, umbral: int):
    if not has_admin_permissions(interaction.user):
        await interaction.response.send_message(
            "❌ Solo usuarios con permisos de administrador pueden usar este comando.",
            ephemeral=True)
        return

    if umbral < 0 or umbral > 100:
        await interaction.response.send_message(
            "❌ El umbral debe estar entre 0 y 100", ephemeral=True)
        return

    config = get_server_config(interaction.guild.id)
    config['risk_threshold'] = umbral
    save_config()

    await interaction.response.send_message(
        f"✅ Umbral de riesgo configurado: {umbral}/100", ephemeral=True)


@bot.tree.command(
    name="deteccion_avanzada",
    description="Activar/desactivar detección avanzada de comportamiento")
async def deteccion_avanzada(interaction: discord.Interaction, estado: str):
    if not has_admin_permissions(interaction.user):
        await interaction.response.send_message(
            "❌ Solo usuarios con permisos de administrador pueden usar este comando.",
            ephemeral=True)
        return

    if estado.lower() not in ['on', 'off', 'activar', 'desactivar']:
        await interaction.response.send_message(
            "❌ Usa: on/off o activar/desactivar", ephemeral=True)
        return

    config = get_server_config(interaction.guild.id)
    config['advanced_detection'] = estado.lower() in ['on', 'activar']
    save_config()

    status = "activada" if config['advanced_detection'] else "desactivada"
    await interaction.response.send_message(f"✅ Detección avanzada {status}",
                                            ephemeral=True)


@bot.tree.command(
    name="cuarentena_rol",
    description="Configurar rol de cuarentena para usuarios sospechosos")
async def cuarentena_rol(interaction: discord.Interaction, rol: discord.Role):
    if not has_admin_permissions(interaction.user):
        await interaction.response.send_message(
            "❌ Solo usuarios con permisos de administrador pueden usar este comando.",
            ephemeral=True)
        return

    config = get_server_config(interaction.guild.id)
    config['quarantine_role'] = rol.id
    save_config()

    await interaction.response.send_message(
        f"✅ Rol de cuarentena configurado: {rol.mention}", ephemeral=True)


@bot.tree.command(name="estadisticas",
                  description="Ver estadísticas de seguridad del servidor")
async def estadisticas(interaction: discord.Interaction):
    if not has_admin_permissions(interaction.user):
        await interaction.response.send_message(
            "❌ Solo usuarios con permisos de administrador pueden usar este comando.",
            ephemeral=True)
        return

    # Calcular estadísticas
    total_users = len(user_activity)
    high_risk_users = sum(1 for activity in user_activity.values()
                          if activity.get('risk_score', 0) > 50)
    suspicious_messages = sum(
        len([
            msg for msg in activity['messages']
            if msg.get('suspicious', False)
        ]) for activity in user_activity.values())

    embed = discord.Embed(title="📊 Estadísticas de Seguridad",
                          color=discord.Color.green())

    embed.add_field(name="👥 Usuarios monitoreados",
                    value=total_users,
                    inline=True)
    embed.add_field(name="⚠️ Usuarios de alto riesgo",
                    value=high_risk_users,
                    inline=True)
    embed.add_field(name="🗑️ Mensajes sospechosos",
                    value=suspicious_messages,
                    inline=True)

    # Estadísticas de raid
    raid_indicators = detect_raid_pattern(interaction.guild.id)
    active_indicators = sum(1 for indicator in raid_indicators.values()
                            if indicator)

    embed.add_field(name="🚨 Indicadores de raid activos",
                    value=active_indicators,
                    inline=True)

    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="lista_riesgo",
                  description="Ver lista de usuarios con alto riesgo")
async def lista_riesgo(interaction: discord.Interaction):
    if not has_admin_permissions(interaction.user):
        await interaction.response.send_message(
            "❌ Solo usuarios con permisos de administrador pueden usar este comando.",
            ephemeral=True)
        return

    high_risk_users = []
    for user_id, activity in user_activity.items():
        risk_score = activity.get('risk_score', 0)
        if risk_score > 50:
            try:
                user = await bot.fetch_user(user_id)
                high_risk_users.append((user, risk_score))
            except:
                continue

    if not high_risk_users:
        await interaction.response.send_message(
            "✅ No hay usuarios de alto riesgo actualmente.", ephemeral=True)
        return

    embed = discord.Embed(
        title="⚠️ Usuarios de Alto Riesgo",
        description="Usuarios con puntuación de riesgo > 50:",
        color=discord.Color.orange())

    for user, risk_score in sorted(high_risk_users,
                                   key=lambda x: x[1],
                                   reverse=True)[:10]:
        embed.add_field(name=f"{user.name} ({user.id})",
                        value=f"Riesgo: {risk_score}/100",
                        inline=False)

    await interaction.response.send_message(embed=embed, ephemeral=True)


# Comandos existentes actualizados
@bot.tree.command(name="canal_alertas",
                  description="Configurar canal de alertas de seguridad")
async def canal_alertas(interaction: discord.Interaction,
                        canal: discord.TextChannel):
    if not has_admin_permissions(interaction.user):
        await interaction.response.send_message(
            "❌ Solo usuarios con permisos de administrador pueden usar este comando.",
            ephemeral=True)
        return

    config = get_server_config(interaction.guild.id)
    config['alert_channel'] = canal.id
    save_config()

    await interaction.response.send_message(
        f"✅ Canal de alertas configurado: {canal.mention}", ephemeral=True)


@bot.tree.command(
    name="auto_ban",
    description="Activar/desactivar auto-ban de usuarios sospechosos")
async def auto_ban(interaction: discord.Interaction, estado: str):
    if not has_admin_permissions(interaction.user):
        await interaction.response.send_message(
            "❌ Solo usuarios con permisos de administrador pueden usar este comando.",
            ephemeral=True)
        return

    if estado.lower() not in ['on', 'off', 'activar', 'desactivar']:
        await interaction.response.send_message(
            "❌ Usa: on/off o activar/desactivar", ephemeral=True)
        return

    config = get_server_config(interaction.guild.id)
    config['auto_ban'] = estado.lower() in ['on', 'activar']
    save_config()

    status = "activado" if config['auto_ban'] else "desactivado"
    await interaction.response.send_message(f"✅ Auto-ban {status}",
                                            ephemeral=True)


@bot.tree.command(name="limite_menciones",
                  description="Configurar límite de menciones por mensaje")
async def limite_menciones(interaction: discord.Interaction, limite: int):
    if not has_admin_permissions(interaction.user):
        await interaction.response.send_message(
            "❌ Solo usuarios con permisos de administrador pueden usar este comando.",
            ephemeral=True)
        return

    if limite < 1 or limite > 20:
        await interaction.response.send_message(
            "❌ El límite debe estar entre 1 y 20", ephemeral=True)
        return

    config = get_server_config(interaction.guild.id)
    config['mention_limit'] = limite
    save_config()

    await interaction.response.send_message(
        f"✅ Límite de menciones configurado: {limite}", ephemeral=True)


@bot.tree.command(
    name="filtro_links",
    description="Activar/desactivar filtro de enlaces maliciosos")
async def filtro_links(interaction: discord.Interaction, estado: str):
    if not has_admin_permissions(interaction.user):
        await interaction.response.send_message(
            "❌ Solo usuarios con permisos de administrador pueden usar este comando.",
            ephemeral=True)
        return

    if estado.lower() not in ['on', 'off', 'activar', 'desactivar']:
        await interaction.response.send_message(
            "❌ Usa: on/off o activar/desactivar", ephemeral=True)
        return

    config = get_server_config(interaction.guild.id)
    config['link_filter'] = estado.lower() in ['on', 'activar']
    save_config()

    status = "activado" if config['link_filter'] else "desactivado"
    await interaction.response.send_message(f"✅ Filtro de enlaces {status}",
                                            ephemeral=True)


@bot.tree.command(name="deteccion_raids",
                  description="Activar/desactivar detección de raids")
async def deteccion_raids(interaction: discord.Interaction, estado: str):
    if not has_admin_permissions(interaction.user):
        await interaction.response.send_message(
            "❌ Solo usuarios con permisos de administrador pueden usar este comando.",
            ephemeral=True)
        return

    if estado.lower() not in ['on', 'off', 'activar', 'desactivar']:
        await interaction.response.send_message(
            "❌ Usa: on/off o activar/desactivar", ephemeral=True)
        return

    config = get_server_config(interaction.guild.id)
    config['raid_detection'] = estado.lower() in ['on', 'activar']
    save_config()

    status = "activado" if config['raid_detection'] else "desactivado"
    await interaction.response.send_message(f"✅ Detección de raids {status}",
                                            ephemeral=True)


@bot.tree.command(name="estado",
                  description="Ver configuración actual de seguridad")
async def estado(interaction: discord.Interaction):
    if not has_admin_permissions(interaction.user):
        await interaction.response.send_message(
            "❌ Solo usuarios con permisos de administrador pueden usar este comando.",
            ephemeral=True)
        return

    config = get_server_config(interaction.guild.id)

    embed = discord.Embed(title="🛡️ Estado de Seguridad - Exside",
                          color=discord.Color.green())

    # Canal de alertas
    alert_channel = None
    if config.get('alert_channel'):
        alert_channel = interaction.guild.get_channel(config['alert_channel'])

    embed.add_field(
        name="📢 Canal de Alertas",
        value=alert_channel.mention if alert_channel else "No configurado",
        inline=True)

    embed.add_field(name="🔨 Auto-ban",
                    value="✅ Activado"
                    if config.get('auto_ban', True) else "❌ Desactivado",
                    inline=True)

    embed.add_field(name="🎯 Umbral de Riesgo",
                    value=f"{config.get('risk_threshold', 75)}/100",
                    inline=True)

    embed.add_field(name="📊 Detección Avanzada",
                    value="✅ Activada" if config.get(
                        'advanced_detection', True) else "❌ Desactivada",
                    inline=True)

    embed.add_field(name="🔗 Filtro de Enlaces",
                    value="✅ Activado"
                    if config.get('link_filter', True) else "❌ Desactivado",
                    inline=True)

    embed.add_field(name="🚨 Detección de Raids",
                    value="✅ Activada"
                    if config.get('raid_detection', True) else "❌ Desactivada",
                    inline=True)

    # Rol de cuarentena
    quarantine_role = None
    if config.get('quarantine_role'):
        quarantine_role = interaction.guild.get_role(config['quarantine_role'])

    embed.add_field(
        name="🔒 Rol de Cuarentena",
        value=quarantine_role.mention if quarantine_role else "No configurado",
        inline=True)

    embed.add_field(name="💬 Límite de Menciones",
                    value=config.get('mention_limit', 3),
                    inline=True)

    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="ban_manual",
                  description="Banear usuario manualmente del servidor")
async def ban_manual(interaction: discord.Interaction,
                     usuario: discord.Member,
                     razon: str = "Baneado por seguridad"):
    if not has_admin_permissions(interaction.user):
        await interaction.response.send_message(
            "❌ Solo usuarios con permisos de administrador pueden usar este comando.",
            ephemeral=True)
        return

    try:
        # Solo ban local
        await usuario.ban(
            reason=f"Ban manual por {interaction.user.name}: {razon}")

        # Enviar notificación al usuario
        await send_ban_notification(usuario,
                                    is_global=False,
                                    guild_name=interaction.guild.name,
                                    reason=razon)

        await send_alert(
            interaction.guild,
            f"🔨 **{usuario.name}** ha sido baneado manualmente por {interaction.user.mention}\n**Razón**: {razon}",
            usuario,
            priority="normal")

        await interaction.response.send_message(
            f"✅ {usuario.name} ha sido baneado del servidor.", ephemeral=True)

    except discord.Forbidden:
        await interaction.response.send_message(
            "❌ No pude banear a este usuario. Verifica mis permisos.",
            ephemeral=True)


# Clase para el modal de unban global
class UnbanGlobalModal(discord.ui.Modal, title='Remover Ban Global'):

    def __init__(self):
        super().__init__()

    user_id = discord.ui.TextInput(
        label='ID del Usuario',
        placeholder='Ingresa el ID del usuario a desbanear...',
        required=True,
        max_length=20)

    reason = discord.ui.TextInput(
        label='Razón del Unban',
        placeholder='¿Por qué se remueve el ban global?',
        required=True,
        style=discord.TextStyle.paragraph,
        max_length=500)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            user_id_int = int(self.user_id.value)

            if user_id_int in global_bans:
                global_bans.remove(user_id_int)
                save_config()

                # Intentar obtener información del usuario
                try:
                    user = await bot.fetch_user(user_id_int)
                    user_name = f"{user.name} ({user.id})"
                except:
                    user_name = f"Usuario desconocido ({user_id_int})"

                # Embed de confirmación
                embed = discord.Embed(
                    title="✅ Ban Global Removido",
                    description="El ban global ha sido removido exitosamente",
                    color=discord.Color.green(),
                    timestamp=datetime.utcnow())

                embed.add_field(name="👤 Usuario", value=user_name, inline=True)

                embed.add_field(name="🛡️ Removido por",
                                value=interaction.user.mention,
                                inline=True)

                embed.add_field(name="📝 Razón",
                                value=self.reason.value,
                                inline=False)

                embed.add_field(
                    name="⚠️ Nota Importante",
                    value=
                    "El usuario debe ser desbaneado manualmente de cada servidor si es necesario.",
                    inline=False)

                await interaction.response.send_message(embed=embed,
                                                        ephemeral=True)

                # Enviar alerta al canal de alertas
                await send_alert(
                    interaction.guild,
                    f"🔓 **Ban global removido**\n**Usuario**: {user_name}\n**Removido por**: {interaction.user.mention}\n**Razón**: {self.reason.value}",
                    priority="normal")

            else:
                embed = discord.Embed(
                    title="❌ Usuario No Encontrado",
                    description="Este usuario no tiene un ban global activo.",
                    color=discord.Color.red())
                await interaction.response.send_message(embed=embed,
                                                        ephemeral=True)

        except ValueError:
            embed = discord.Embed(
                title="❌ ID Inválido",
                description="El ID de usuario ingresado no es válido.",
                color=discord.Color.red())
            await interaction.response.send_message(embed=embed,
                                                    ephemeral=True)


# Vista para el botón de unban global
class UnbanGlobalView(discord.ui.View):

    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label='🔓 Remover Ban Global',
                       style=discord.ButtonStyle.danger,
                       custom_id='unban_global_button')
    async def unban_global_button(self, interaction: discord.Interaction,
                                  button: discord.ui.Button):
        # Verificar servidor AUTORIZADO para panel unban
        if interaction.guild.id != 1391384362381217812:
            await interaction.response.send_message(
                "❌ El panel de unban global no está disponible en este servidor.",
                ephemeral=True)
            return

        # Verificar permisos
        if not has_admin_permissions(interaction.user):
            await interaction.response.send_message(
                "❌ Solo usuarios con permisos de administrador pueden usar esta función.",
                ephemeral=True)
            return

        # Mostrar modal
        modal = UnbanGlobalModal()
        await interaction.response.send_modal(modal)


@bot.tree.command(name="lista_bans_globales",
                  description="Ver lista de usuarios con ban global")
async def lista_bans_globales(interaction: discord.Interaction):
    if not has_admin_permissions(interaction.user):
        await interaction.response.send_message(
            "❌ Solo usuarios con permisos de administrador pueden usar este comando.",
            ephemeral=True)
        return

    if not global_bans:
        await interaction.response.send_message(
            "✅ No hay usuarios con ban global actualmente.", ephemeral=True)
        return

    embed = discord.Embed(
        title="🚫 Lista de Bans Globales",
        description=
        f"Usuarios con ban global activo ({len(global_bans)} total):",
        color=discord.Color.red())

    ban_list = []
    for user_id in list(global_bans)[:20]:  # Mostrar máximo 20
        try:
            user = await bot.fetch_user(user_id)
            ban_list.append(f"• {user.name} ({user_id})")
        except:
            ban_list.append(f"• Usuario desconocido ({user_id})")

    if ban_list:
        embed.add_field(name="Usuarios:",
                        value="\n".join(ban_list),
                        inline=False)

    if len(global_bans) > 20:
        embed.add_field(
            name="Nota:",
            value=
            f"Mostrando 20 de {len(global_bans)} usuarios. Usa el panel en el servidor de soporte para remover bans.",
            inline=False)

    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="info_bot",
                  description="Información del bot de seguridad Exside")
async def info_bot(interaction: discord.Interaction):
    embed = discord.Embed(
        title="🛡️ Exside - Bot de Seguridad Avanzado",
        description="Sistema de seguridad inteligente 24/7 para Discord",
        color=discord.Color.blue())

    embed.add_field(name="🔥 Funciones Avanzadas:",
                    value="""
        • **Detección con IA**: Análisis de comportamiento en tiempo real
        • **Sistema de Puntuación**: Evaluación de riesgo por usuario
        • **Detección de Raids**: Patrones de ataques coordinados
        • **Filtros Inteligentes**: Contenido malicioso y scams
        • **Cuarentena Automática**: Usuarios sospechosos
        • **Alertas Inteligentes**: Notificaciones por niveles
        """,
                    inline=False)

    embed.add_field(name="⚡ Rendimiento:",
                    value=f"Latencia: {round(bot.latency * 1000)}ms",
                    inline=True)

    embed.add_field(name="🏆 Versión:", value="2.0 Advanced", inline=True)

    await interaction.response.send_message(embed=embed)


# Comando para obtener el token
@bot.command(name='setup')
async def setup(ctx):
    """Información de configuración inicial"""
    if not await is_admin(ctx):
        return

    embed = discord.Embed(title="🔧 Configuración Inicial - Exside",
                          description="Para usar este bot necesitas:",
                          color=discord.Color.gold())

    embed.add_field(
        name="1. Token del Bot",
        value=
        "Ve a https://discord.com/developers/applications y crea una aplicación",
        inline=False)

    embed.add_field(
        name="2. Permisos necesarios",
        value=
        "• Ban Members\n• Kick Members\n• Manage Messages\n• Manage Roles\n• View Channels\n• Send Messages",
        inline=False)

    embed.add_field(
        name="3. Configuración básica",
        value=
        "• `/canal_alertas #tu-canal`\n• `/cuarentena_rol @rol`\n• `/umbral_riesgo 75`",
        inline=False)

    await ctx.send(embed=embed)


if __name__ == "__main__":
    # El token debe ser configurado como secreto en Replit
    token = os.getenv('DISCORD_BOT_TOKEN')

    if not token:
        print(
            "❌ Error: DISCORD_BOT_TOKEN no encontrado en las variables de entorno"
        )
        print(
            "📝 Ve a la pestaña 'Secrets' en Replit y añade tu token de Discord"
        )
        exit(1)

    try:
        bot.run(token)
    except discord.LoginFailure:
        print("❌ Error: Token de Discord inválido")
    except Exception as e:
        print(f"❌ Error al ejecutar el bot: {e}")


async def setup_server_roles(guild):
    """Crear roles necesarios para el bot en un servidor"""
    try:
        if not guild.me.guild_permissions.manage_roles:
            print(f"❌ Sin permisos para crear roles en {guild.name}")
            return

        # Rol de cuarentena
        quarantine_role_name = "🔒 Cuarentena - Exside"
        quarantine_role = discord.utils.get(guild.roles,
                                            name=quarantine_role_name)

        if not quarantine_role:
            quarantine_permissions = discord.Permissions(
                read_messages=True,
                send_messages=False,
                add_reactions=False,
                connect=False,
                speak=False,
                create_instant_invite=False,
                change_nickname=False)

            quarantine_role = await guild.create_role(
                name=quarantine_role_name,
                permissions=quarantine_permissions,
                color=discord.Color.dark_grey(),
                hoist=False,
                mentionable=False,
                reason="Rol de cuarentena para usuarios sospechosos")
            print(
                f"✅ Rol de cuarentena creado: {quarantine_role_name} en {guild.name}"
            )

        # Asignar el rol de integración "Exside" al bot automáticamente
        exside_role_name = "Exside"  # Nombre del rol a asignar
        exside_role = discord.utils.get(guild.roles, name=exside_role_name)

        if exside_role:
            await guild.me.add_roles(exside_role)
            print(
                f"✅ Rol asignado automáticamente al bot: {exside_role_name} en {guild.name}"
            )

        # Configurar automáticamente el rol de cuarentena
        config = get_server_config(guild.id)
        config['quarantine_role'] = quarantine_role.id
        save_config()

    except Exception as e:
        print(f"❌ Error en setup_server_roles: {e}")
