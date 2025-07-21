#!/usr/bin/env python3

import base64
import hashlib
import hmac
import http.cookiejar
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlencode, urlparse

import requests

from config import chat_id, sleep, token, topic, languages_to_get

logging.basicConfig(level=logging.INFO)


def send_notification(msg):
    if msg:
        url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
        params = {
            "text": msg,
            **({"message_thread_id": TOPIC} if TOPIC else {}),
            "chat_id": CHAT_ID,
            "parse_mode": "html",
            "disable_web_page_preview": True,
        }
        res = requests.post(url, params=params)

        c = 1
        while res.status_code != 200 and c < 5:
            time.sleep(5)
            res = requests.post(url, params=params)
            c += 1
        if c == 5:
            raise Exception(res.text)


def calculate_signature(key, msg):
    digest = hmac.new(key, msg.encode(), hashlib.sha256).digest()
    return base64.b64encode(digest)


def generate_signed_url(base_url: str, params: dict, secret: str) -> str:
    params = {
        k: v for k, v in params.items() if k not in ["signature", "signature_protocol"]
    }

    parsed_url = urlparse(base_url)
    cleaned_url = parsed_url._replace(query=urlencode(params)).geturl()

    now = datetime.now(timezone.utc)
    date_suffix = f"{now.year}{now.month:02d}{now.day:02d}"

    key = secret.encode("utf-8")
    signature = calculate_signature(key, cleaned_url + date_suffix)

    params["signature"] = signature
    params["signature_protocol"] = "sha256"
    final_url = parsed_url._replace(query=urlencode(params)).geturl()

    return final_url


def get_client_key() -> str:
    # they might change this in the future, so we keep this version
    obfuscated = "=gTO1kDZ2QDO4UjM3YzMlFWOmhTZjdDNiVWYxATM0QWY"
    reversed_str = obfuscated[::-1]
    decoded_bytes = base64.b64decode(reversed_str)
    return decoded_bytes.decode("utf-8")


def load_cookies():
    cookie_jar = http.cookiejar.MozillaCookieJar()
    cookie_jar.load("cookies.txt", ignore_discard=True, ignore_expires=True)

    return {cookie.name: cookie.value for cookie in cookie_jar}


def get_auth_token(headers, token):
    secret = get_client_key()
    base_url = "https://curators-beta.musixmatch.com/ws/1.1/jwt.get"
    params = {
        "app_id": "web-desktop-app-v1.0",
        "usertoken": token,
    }

    url = generate_signed_url(base_url, params, secret)

    try:
        res = requests.get(url, headers=headers).json()
    except Exception as e:
        logging.error(f"Error fetching auth token: {e}")
        return ""

    return res["message"]["body"]["jwt"]


def get_user_token(cookies):
    tokens = json.loads(unquote(cookies["musixmatchUserToken"]))
    return tokens["tokens"]["web-desktop-app-v1.0"]


def get_user_id(cookies):
    tokens = json.loads(
        unquote([y for x, y in cookies.items() if "user_id" in str(y)][0])
    )
    return tokens["distinct_id"]


def load_cache(cache_file):
    if cache_file.exists():
        try:
            data = json.loads(cache_file.read_text())
        except Exception:
            return {}

        for key, value in data.items():
            data[key] = value

        return data
    return {}


def main():
    log = logging.getLogger("music")

    cache_file = Path("cache.json")
    cache_data = load_cache(cache_file)

    cookie = load_cookies()
    user_token = get_user_token(cookie)
    user_id = get_user_id(cookie)
    headers = {
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.7",
        "cache-control": "no-cache",
        "content-type": "application/json",
        "origin": "https://curators-beta.musixmatch.com",
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": "https://curators-beta.musixmatch.com/",
        "sec-ch-ua": '"Chromium";v="136", "Brave";v="136", "Not.A/Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "sec-gpc": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "x-amz-user-agent": "aws-amplify/3.0.7",
        "x-mxm-app-version": "1.180.0",
    }
    headers["authorization"] = get_auth_token(headers, user_token)

    while True:
        try:
            res = requests.post(
                url=GRAPHQL_URL,
                headers=headers,
                json={
                    "operationName": "AvailableMissionsList",
                    "variables": {
                        "appId": "web-desktop-app-v1.0",
                        "userId": user_id,
                        "userToken": user_token,
                    },
                    "query": "query AvailableMissionsList($appId: String, $userId: ID, $userToken: String) {\n  getAvailableMissions(input: {appId: $appId, userId: $userId, userToken: $userToken}) {\n    items {\n      accessRules {\n        actions\n        roles\n        __typename\n      }\n      task\n      id\n      badges {\n        image_url_large\n        image_url_small\n        name\n        __typename\n      }\n      categories\n      description\n      duration\n      expiry\n      lastUpdated\n      missionId\n      num_tasks_target\n      title\n      userProgress {\n        id\n        deadline\n        lastUpdated\n        missionId\n        num_tasks_completed\n        status\n        __typename\n      }\n      __typename\n    }\n    nextToken\n    __typename\n  }\n}\n",
                },
            )
            res.raise_for_status()
        except requests.exceptions.HTTPError as e:
            error = (
                e.response.json().get("errors", [{}])[0].get("message", "Unknown error")
            )
            log.error(f"HTTP error occurred: {error}")
            headers["authorization"] = get_auth_token(headers, user_token)
            continue
        except Exception as e:
            log.error(e)
            continue

        try:
            res = res.json()
        except json.JSONDecodeError as e:
            log.error(f"Failed to decode JSON response: {e}")
            continue

        items = res.get("data", {}).get("getAvailableMissions", {}).get("items", [])
        for item in items:
            title = item["title"]
            if not cache_data.get(title):
                cache_data[title] = []

            try:
                res = requests.post(
                    GRAPHQL_URL,
                    headers=headers,
                    json={
                        "operationName": "LyricsList",
                        "variables": {
                            "limit": 25,
                            "nextToken": None,
                            "sortAscending": True,
                            "sortBy": "language",
                            "status": "AVAILABLE",
                            "appId": "web-desktop-app-v1.0",
                            "missionId": item["missionId"],
                            "userToken": user_token,
                            "languages": "hu",  # u0,hu,en
                        },
                        "query": 'query LyricsList($appId: String, $languages: String, $destinationLanguage: String, $limit: Int = 25, $missionId: String, $nextToken: String = null, $sortAscending: Boolean = true, $sortBy: String = "rank", $status: String = "AVAILABLE", $userToken: String) {\n  getSortedLyrics(appId: $appId, languages: $languages, destinationLanguage: $destinationLanguage, limit: $limit, missionId: $missionId, nextToken: $nextToken, sortForward: $sortAscending, sortBy: $sortBy, status: $status, userToken: $userToken) {\n    items {\n      id\n      actionURI\n      artistName\n      commonTrackId\n      hasLyrics\n      hasSync\n        lastUpdated\n      language\n      missionId\n      publishedStatusMacro\n      rank\n      status\n      title\n      trackLength\n      trackLengthMs\n      destinationLanguage\n      __typename\n    }\n    nextToken\n    __typename\n  }\n}\n',
                    },
                ).json()
            except Exception as e:
                log.error(f"Error fetching lyrics: {e}")

            mission_items = (
                res.get("data", {}).get("getSortedLyrics", {}).get("items", [])
            )

            for mission_item in mission_items:
                if mission_item["commonTrackId"] not in cache_data[title]:
                    send_notification(
                        f'{item["title"]} - {mission_item["artistName"]} - {mission_item["title"]} - <a href="https://www.musixmatch.com/lyrics/{mission_item["artistName"].replace(" ", "-")}/{mission_item["title"].replace(" ", "-")}">{mission_item["commonTrackId"]}</a>',
                    )
                    cache_data[title].append(mission_item["commonTrackId"])
                    cache_file.write_text(json.dumps(cache_data, indent=4))

        time.sleep(SLEEP)


if __name__ == "__main__":
    CHAT_ID = chat_id
    TOPIC = topic
    TOKEN = token
    SLEEP = sleep
    LANGUAGE_TO_GET = languages_to_get
    GRAPHQL_URL = "https://missions-backend-new.musixmatch.com/graphql"
    main()
