import telebot
from telebot import types
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import datetime
import os
import time
# Bot initialization with Telegram API token
bot = telebot.TeleBot('6945433492:AAHPvr6R1tqKiyyzAtZ2N2kcOy6AncEe5QY')

# Owner ID
OWNER_CHAT_ID = 5460343986

# Group ID
GROUP_ID = -1001685012914

# Set of users who have started the bot
users_set = set()

# Inline keyboard markup for menu
menu_markup = types.InlineKeyboardMarkup(row_width=2)
menu_markup.add(types.InlineKeyboardButton(text="Join Group", url=f"https://t.me/indian_hacker_group"))

# Inline keyboard markup for help menu
help_markup = types.InlineKeyboardMarkup()
help_markup.add(types.InlineKeyboardButton(text="Help", callback_data="help"))
# Logs directory setup
if not os.path.exists('logs'):
    os.makedirs('logs')

# Payloads directory setup
if not os.path.exists('payloads'):
    os.makedirs('payloads')
# /start command handler
@bot.message_handler(commands=['start'])
def send_welcome(message):
    chat_id = message.chat.id
    user_id = message.from_user.id
    users_set.add(user_id)
    
    if message.chat.type == 'private':
        if is_group_member(user_id):
            bot.send_message(chat_id, "Welcome to Web Penetration Testing Bot!\n"
                                      "Use the menu below to perform scans or click 'Help' for guidance.", reply_markup=menu_markup)
        else:
            bot.send_message(chat_id, "Please join the group to access the bot features.",
                             reply_markup=menu_markup)
    else:
        pass  # Do not reply in group chats

# Check if user is a member of the group
def is_group_member(user_id):
    try:
        member_status = bot.get_chat_member(GROUP_ID, user_id).status
        return member_status in ['member', 'administrator', 'creator']
    except Exception as e:
        print(f"Error checking group membership: {e}")
        return False
# Ensure group membership for all button presses
def ensure_group_membership(func):
    def wrapper(call):
        user_id = call.from_user.id
        if not is_group_member(user_id):
            bot.send_message(user_id, "Please join the group to access the bot features.",
                                reply_markup=menu_markup)
        else:
            func(call)
    return wrapper
# Inline menu callback handler with animated progress
@bot.callback_query_handler(func=lambda call: True)
@ensure_group_membership
def handle_menu(call):
    chat_id = call.message.chat.id
    user_id = call.from_user.id
    username = call.from_user.username or call.from_user.first_name

    if call.data == 'help':
        bot.send_message(user_id, "Welcome to Web Penetration Testing Bot!\n"
                                  "You can perform various scans and checks using the menu buttons:\n"
                                  "- Click 'XSS Scanning' to check for Cross-Site Scripting vulnerabilities.\n"
                                  "- Click 'SQL Injection Scanning' to check for SQL Injection vulnerabilities.\n"
                                  "- Click 'CSRF Check' to check for Cross-Site Request Forgery vulnerabilities.\n"
                                  "- Click 'Directory Traversal Check' to check for path traversal vulnerabilities.\n"
                                  "- Click 'SSL/TLS Analysis' to analyze SSL/TLS configuration.\n"
                                  "- Click 'Header Analysis' to analyze HTTP headers for security.\n"
                                  "- Click 'Sensitive Data Check' to find exposed sensitive information.\n"
                                  "- Click 'DOM-based XSS Check' to perform DOM-based XSS vulnerability checks.\n"
                                  "- Click 'Authentication Testing' to test authentication mechanisms.\n"
                                  "- Click 'Perform Full Scan' to initiate a comprehensive scan.\n"
                                  "Feel free to explore and analyze different aspects of web security!",
                         reply_markup=menu_markup)
    elif call.data == 'contact_owner':
        bot.send_message(user_id, "Please type your message to the owner.")
        bot.register_next_step_handler(call.message, send_message_to_owner)
    elif call.data in ['xss', 'sqli', 'csrf', 'dir_traversal', 'ssl_tls', 'header_analysis', 'sensitive_data', 'dom_xss', 'auth_test']:
        message = bot.send_message(user_id, f"Send me a URL to scan for {call.data.replace('_', ' ').upper()} vulnerabilities.")
        simulate_scan_animation(message)
    elif call.data == 'full_scan':
        message = bot.send_message(user_id, "Please send the URL for the full scan.")
        simulate_scan_animation(message)
    else:
        bot.send_message(user_id, "Unknown action.")
# Simulate scan animation with percentage
def simulate_scan_animation(message):
    animation_text = "ꀮꀲꁗꁘꁟꁠꁞꁯꁮꁱꂐꂏꂠꂘꃍ"
    percentage = 0
    while percentage <= 100:
        animation_progress = f"{animation_text} {percentage}%"
        bot.edit_message_text(chat_id=message.chat.id, message_id=message.message_id, text=animation_progress)
        time.sleep(0.5)  # Adjust animation speed if needed
        percentage += 10
# Function to send message to owner
def send_message_to_owner(message):
    user_id = message.from_user.id
    username = message.from_user.username or message.from_user.first_name
    message_to_owner = message.text
    bot.send_message(OWNER_CHAT_ID, f"Message from {username} ({user_id}):\n\n{message_to_owner}")
    bot.send_message(user_id, "Your message has been sent to the owner.")
# Invalid URL handling
@bot.message_handler(func=lambda message: not message.text.startswith('http'))
def handle_invalid_url(message):
    chat_id = message.chat.id
    if message.chat.type == 'private':
        bot.send_message(chat_id, "The URL you provided seems to be invalid. Please ensure it starts with http or https.")
# Load payloads for specific scan types
def load_payloads(scan_type):
    payloads = []
    payloads_directory = 'payloads'

    if scan_type == 'xss':
        with open(os.path.join(payloads_directory, 'xss_payloads.txt'), 'r') as file:
            payloads = file.read().splitlines()
    elif scan_type == 'sqli':
        with open(os.path.join(payloads_directory, 'sqli_payloads.txt'), 'r') as file:
            payloads = file.read().splitlines()
    # Add more conditions for other scan types as needed

    return payloads
# Perform scan by type with payloads
def perform_scan_by_type(scan_type, url, payloads):
    if scan_type == 'xss':
        return check_xss(url, payloads)
    elif scan_type == 'sqli':
        return check_sqli(url, payloads)
    # Add more conditions for other scan types as needed

# Specific scan functions
def check_xss(url, payloads):
    # Implement XSS scan logic
    return "XSS scan result"

def check_sqli(url, payloads):
    # Implement SQLi scan logic
    return "SQL Injection scan result"
# Notify critical vulnerability
def notify_critical_vulnerability(username, url, scan_type, vulnerability):
    owner_message = (
        f"🚨 Critical Vulnerability Detected! 🚨\n\n"
        f"User: {username}\n"
        f"URL: {url}\n"
        f"Scan Type: {scan_type.upper()}\n"
        f"Vulnerability: {vulnerability}\n"
        f"Timestamp: {datetime.datetime.now()}\n"
    )
    bot.send_message(OWNER_CHAT_ID, owner_message)
    bot.send_message(username, owner_message)
# Perform full scan
def perform_full_scan(chat_id):
    def full_scan_sequence(message):
        url = message.text
        scan_types = ['xss', 'sqli', 'csrf', 'dir_traversal', 'ssl_tls', 'header_analysis', 'sensitive_data', 'dom_xss', 'auth_test']

        for scan_type in scan_types:
            payloads = load_payloads(scan_type)
            result = perform_scan_by_type(scan_type, url, payloads)
            bot.send_message(chat_id, f"Scan result for {scan_type.replace('_', ' ').upper()}:\n{result}")
            log_scan_details(message.from_user.username, url, scan_type, result)
            if "vulnerability" in result.lower():
                capture_and_send_screenshot_by_url(url, scan_type)
                notify_critical_vulnerability(message.from_user.username, url, scan_type, result)

        bot.send_message(chat_id, "Full scan completed.")

    return full_scan_sequence
# Logging scan details
def log_scan_details(username, url, scan_type, result):
    log_file = f"logs/{datetime.datetime.now().strftime('%Y-%m-%d')}_scan_log.txt"
    log_entry = f"User: {username}\nURL: {url}\nScan Type: {scan_type}\nResult:\n{result}\nTimestamp: {datetime.datetime.now()}\n\n"
    
    with open(log_file, 'a') as file:
        file.write(log_entry)
# Command to contact owner
@bot.message_handler(commands=['contact_owner'])
@ensure_group_membership
def contact_owner(message):
    bot.send_message(message.chat.id, "Please type your message to the owner.")
    bot.register_next_step_handler(message, send_message_to_owner)
# Command to handle unknown inputs
@bot.message_handler(func=lambda message: True)
@ensure_group_membership
def handle_unknown(message):
    bot.send_message(message.chat.id, "Unknown command. Use the menu to interact with the bot.")
# Start polling
bot.polling()
