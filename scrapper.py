import email
import imaplib
import json
import logging
import re
from copy import deepcopy
from datetime import datetime, timedelta
from time import sleep
from urllib.parse import urljoin

import cfscrape
import requests as rq
from websocket import create_connection as ws_create_connection
from python_anticaptcha import AnticaptchaClient, NoCaptchaTaskProxylessTask


def match_or_empty(rgx, html):
    match = rgx.search(html)
    if match:
        res = match.group(1)
    else:
        res = ""
    return res


class SomeClass(object):
    base_url = "https://site.com/"
    auth_url = "https://site.com/auth"
    wallet_url = "https://site.com/wallet"
    orders_page = "https://site.com/wallet/orders"
    close_order_url = "https://site.com/exchange/api/remove-order"
    withdraw_url = "https://site.com/wallet/withdraw/"
    websocket_server = "wss://site.com/wss2/NNN:8080"
    site_username = "user"
    site_user_email = "user@gmail.com"
    site_user_password = "123"
    anticaptcha_api_key = "123"
    email_login = "user"
    email_password = "123"
    smtp_server = "imap.gmail.com"
    smtp_port = 993
    login_retry_limit = 5
    http_retry_limit = 5
    redirects_codes_list = [301, 302, 303, 307, 308]
    ua = "Mozilla/5.0 (X11; Linux x86_64; rv:67.0) Gecko/20100101 Firefox/67.0"
    headers = {
        "Host": "site.com",
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml" ";q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en-US;q=0.7,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "DNT": "1",
        "Connection": "keep-alive",
        "Cookie": None,
        "Upgrade-Insecure-Requests": "1",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
    }
    auth_form_body = {
        "_csrf": None,
        "Client[email]": site_user_email,
        "Client[password]": site_user_password,
        "g-recaptcha-response": None,
    }
    cf_cookies = None
    guest_cookies = None
    user_cookies = None
    full_cookies = None
    rgx = {
        "csrf_token": re.compile(
            r"name=[\'\"]csrf-token[\'\"] content=[\'\"](.*?)[\'\"]"
        ),
        "csrf_form_token": re.compile(
            r"name=\\[\"\']_csrf\\[\"\'] value=\\[\"\'](.*?)\\[\"\']"
        ),
        "recaptcha_key": re.compile(
            r"class=[\'\"]g-recaptcha[\'\"] data-sitekey=[\'\"](.*?)[\'\"]"
        ),
        "withdraw_error": re.compile(
            r"class=[\'\"]alert alert-danger alert-dismissible[\'\"]"
            r"[\s\S]*?</button>\n(.*?)</div>"
        ),
        "withdraw_success": re.compile(
            r"class=[\'\"]alert alert-dismissible animated wobble[\'\"]"
            r".*\n.*\n<span aria-hidden=[\'\"]true[\'\"]>(OK)</span>"
        ),
        "orders": re.compile(
            r"class=[\'\"]row ord-row[\'\"]([\s\S]*?)"
            r"class=[\'\"]fa fa-times[\'\"]"
        ),
        "order_details": re.compile(
            r"class=[\'\"]col-xs-2 text-center[\'\"]>(.*?)</"
        ),
        "order_id": re.compile(
            r"data-order-id-remove=[\'\"](.*?)[\'\"]"
        ),
        "currency": re.compile(r"Currency:(.*)"),
        "address": re.compile(r"WALLET:(.*)"),
        "amount": re.compile(r"Amount:(.*)"),
        "time": re.compile(r"Created at:(.*)"),
        "confirmation_link": re.compile(
            r"(https://site.com/withdraw/confirm[\s\S]*?)Please"
        ),
    }

    @classmethod
    def get_response(cls, url, s=rq.Session(), method="get", headers=None, data=None):
        limit = deepcopy(cls.http_retry_limit) + 1
        if not headers:
            headers = cls.get_headers()
        success = False
        while not success and cls.http_retry_limit > 0:
            try:
                if method == "get":
                    response = s.get(url, headers=headers, timeout=(30, 30))
                else:
                    response = s.post(
                        url,
                        headers=headers,
                        timeout=(30, 30),
                        data=data,
                        allow_redirects=False,
                    )
            except rq.exceptions.ConnectTimeout:
                logging.error(
                    f"Unable to get {url}: connection timeout\n"
                    f"Attempt {limit - cls.http_retry_limit}"
                )
                cls.http_retry_limit -= 1
                continue
            except rq.exceptions.ReadTimeout:
                logging.error(
                    f"Unable to get {url}: read timeout\n"
                    f"Attempt {limit - cls.http_retry_limit}"
                )
                cls.http_retry_limit -= 1
                continue
            except Exception as e:
                logging.error(
                    f"Unable to get {url}: {e}\n"
                    f"Attempt {limit - cls.http_retry_limit}"
                )
                cls.http_retry_limit -= 1
                continue
            success = True
        if not success:
            cls.http_retry_limit = 5
            return None
        return response

    @classmethod
    def get_headers(cls):
        headers = deepcopy(cls.headers)
        if not cls.guest_cookies:
            headers["Cookie"] = cls.cf_cookies
        elif not cls.full_cookies:
            headers["Cookie"] = f"{cls.cf_cookies}; {cls.guest_cookies}"
        else:
            headers["Cookie"] = cls.full_cookies
        return headers

    @classmethod
    def get_cf_cookies(cls):
        try:
            cls.cf_cookies = cfscrape.get_cookie_string(
                cls.base_url, user_agent=cls.ua
            )[0]
        except Exception as err:
            logging.error(f"Couldn't get cloudflare cookies / {err}")

    @classmethod
    def get_guest_cookies(cls, s):
        cls.get_cf_cookies()
        home_page = cls.get_response(cls.base_url, s)
        if not home_page:
            logging.error(f"Couldn't get guest cookies")
            return
        cls.guest_cookies = " ".join(
            [f"{key}={value};" for key, value in s.cookies.get_dict().items()]
        )

    @classmethod
    def get_csrf_token(cls, page, form=False):
        if not form:
            return match_or_empty(cls.rgx["csrf_token"], page)
        else:
            return match_or_empty(cls.rgx["csrf_form_token"], page)

    @classmethod
    def get_recaptcha_key(cls, page):
        return match_or_empty(cls.rgx["recaptcha_key"], page)

    @classmethod
    def get_recaptcha_response(cls, page):
        try:
            key = cls.get_recaptcha_key(page)
            client = AnticaptchaClient(cls.anticaptcha_api_key)
            task = NoCaptchaTaskProxylessTask(cls.auth_url, key)
            job = client.createTask(task)
            job.join()
            recaptcha_res = job.get_solution_response()
        except Exception as err:
            logging.error(f"Couldn't get recaptcha response  / {err}")
            return ""
        return recaptcha_res

    @classmethod
    def get_auth_form_body(cls, page):
        data = cls.auth_form_body
        data["_csrf"] = cls.get_csrf_token(page)
        data["g-recaptcha-response"] = cls.get_recaptcha_response(page)
        return data

    @classmethod
    def get_auth_form_headers(cls):
        headers = deepcopy(cls.headers)
        headers["Cookie"] = f"{cls.cf_cookies}; {cls.guest_cookies}"
        headers["Referer"] = "https://site.com/auth"
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        return headers

    @classmethod
    def get_auth_form_data(cls, page):
        return (cls.get_auth_form_headers(), cls.get_auth_form_body(page))

    @classmethod
    def save_cookies(cls, cookies):
        cls.user_cookies = " ".join(
            [f"{key}={value};" for key, value in cookies.items() if key != "__cfduid"]
        )
        cls.full_cookies = f"{cls.cf_cookies}; {cls.user_cookies}"

    @classmethod
    def login(cls):
        limit = deepcopy(cls.login_retry_limit)
        logged = False

        while not logged and cls.login_retry_limit > 0:
            s = rq.Session()

            cls.get_guest_cookies(s)

            auth_page = cls.get_response(cls.auth_url, s)
            if not auth_page:
                cls.login_retry_limit -= 1
                continue

            headers, data = cls.get_auth_form_data(auth_page.text)
            auth_post_response = cls.get_response(
                cls.auth_url, s, "post", headers, data
            )
            if not auth_post_response:
                cls.login_retry_limit -= 1
                continue

            if auth_post_response.status_code in cls.redirects_codes_list:
                redirect_location = urljoin(
                    cls.base_url, auth_post_response.headers["Location"]
                )
                wallet_page = cls.get_response(redirect_location, s)
                if not wallet_page:
                    cls.login_retry_limit -= 1
                    continue

                cls.save_cookies(s.cookies.get_dict())

                if cls.check_login(wallet_page.text):
                    cls.login_retry_limit = 5
                    logged = True
                    return True

            cls.login_retry_limit -= 1

        if not logged:
            raise Exception(f"Login failed after {limit} attempts")

    @classmethod
    def check_login(cls, page):
        if page.count(cls.site_username) != 0:
            return True
        else:
            return False

    @classmethod
    def get_1_withdraw_data(cls, page):
        headers = deepcopy(cls.headers)
        headers["Cookie"] = cls.full_cookies
        headers["Referer"] = "https://site.com/wallet"
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        headers["X-Requested-With"] = "XMLHttpRequest"

        data = {"_csrf": cls.get_csrf_token(page)}

        return (headers, data)

    @classmethod
    def get_2_withdraw_data(cls, page, address, amount, btc_fee):
        headers = deepcopy(cls.headers)
        headers["Cookie"] = cls.full_cookies
        headers["Referer"] = "https://site.com/wallet"
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        data = {
            "_csrf": cls.get_csrf_token(page, form=True),
            "address": address,
            "amount": amount,
            "btc_fee": btc_fee,
        }
        if not btc_fee:
            del data["btc_fee"]

        return (headers, data)

    @classmethod
    def check_withdraw_status(cls, page):
        if match_or_empty(cls.rgx["withdraw_success"], page):
            return True
        else:
            error = match_or_empty(cls.rgx["withdraw_error"], page)
            raise Exception(f"Withdraw failed: {error}")

    @classmethod
    def get_withdraw_confirmation_link(cls, currency, address, amount, time):
        sleep(5)
        success = False
        time = time.strftime("%d.%m.%Y %H:%M:%S")
        try:
            mail = imaplib.IMAP4_SSL(cls.smtp_server)
            mail.login(cls.email_login, cls.email_password)
            mail.select("inbox")
            data = mail.search(None, "UNSEEN")
            for i in data[1][0].split():
                data = mail.fetch(i, "(RFC822)")
                msg = email.message_from_string(
                    data[1][0][1].decode("utf-8")
                )
                if msg["subject"] == "site - withdrawal confirmation":
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            text = part.get_payload()
                            if (
                                currency == match_or_empty(
                                    cls.rgx["currency"], text
                                ).strip()
                                and address == match_or_empty(
                                    cls.rgx["address"], text
                                ).strip()
                                and amount == match_or_empty(
                                    cls.rgx["amount"], text
                                ).strip()
                                and time == match_or_empty(
                                    cls.rgx["time"], text
                                ).strip()
                            ):
                                url = match_or_empty(
                                    cls.rgx["confirmation_link"], text
                                ).replace("=\r\n", "").strip()
                                cls.get_response(url)
                                return True
                            else:
                                mail.store(i, '-FLAGS', '(\\Seen)')
                else:
                    mail.store(i, '-FLAGS', '(\\Seen)')
        except Exception as err:
            raise Exception(f"Withdraw failed: {err}")
        if not success:
            raise Exception(f"Withdraw failed: couldn't find message")

    @classmethod
    def withdraw(cls, currency, address, amount, btc_fee):
        s = rq.Session()

        wallet_page = cls.get_response(cls.wallet_url, s)
        if not wallet_page:
            raise Exception("Withdraw failed: connection problems")

        if not cls.check_login(wallet_page.text):
            cls.login()

        headers, data = cls.get_1_withdraw_data(wallet_page.text)
        withdraw_post_res = cls.get_response(
            f"{cls.withdraw_url}{currency}", s, "post", headers, data
        )
        if not withdraw_post_res:
            raise Exception("Withdraw failed: connection problems")

        headers, data = cls.get_2_withdraw_data(
            withdraw_post_res.text, address, amount, btc_fee
        )
        withdraw_post_res = cls.get_response(
            f"{cls.withdraw_url}{currency}", s, "post", headers, data
        )
        created_time = datetime.now() - timedelta(hours=3)
        if not withdraw_post_res:
            raise Exception("Withdraw failed: connection problems")

        if withdraw_post_res.status_code in cls.redirects_codes_list:
            redirect_location = urljoin(
                cls.base_url, withdraw_post_res.headers["Location"]
            )
            wallet_page = cls.get_response(redirect_location, s)
            if not wallet_page:
                raise Exception("Withdraw failed: connection problems")

            if cls.check_withdraw_status(wallet_page.text):
                if cls.get_withdraw_confirmation_link(
                    currency, address, amount, created_time
                ):
                    return True

        raise Exception("Withdraw failed for an unknown reason")

    @classmethod
    def get_make_order_data(cls, action, _type, price, amount, pair_id):
        headers = deepcopy(cls.headers)
        headers["Cookie"] = cls.full_cookies
        headers["Accept"] = '*/*'
        headers["Sec-WebSocket-Version"] = '13'
        headers["Origin"] = 'https://site.com'
        headers["Sec-WebSocket-Extensions"] = 'permessage-deflate'
        headers["Connection"] = 'keep-alive Upgrade'
        headers["Upgrade"] = 'websocket'

        data = {
            "act": 'newOrder',
            "data": {
                "type": _type,
                "price": price,
                "amount": amount,
                "pair_id": pair_id,
                "action": action,
            }
        }

        return (headers, data)

    @classmethod
    def make_order(cls, action, _type, price, amount, pair_id, pair):
        headers, data = cls.get_make_order_data(action, _type, price, amount, pair_id)

        try:
            ws = ws_create_connection(cls.websocket_server, header=headers)
            ws.send(json.dumps(data))
            order_time = datetime.now() - timedelta(hours=3)
        except Exception as err:
            raise Exception(f"Order failed: Couldn't connect to websocket server / {err}")

        try:
            res = ws.recv()
        except Exception:
            res = ""
        if not res:
            if cls.was_order_paid(order_time, action, _type, pair, price, amount):
                return (True, order_time)
            else:
                return (False, order_time)
        else:
            try:
                res = json.loads(res, strict=False)
            except Exception as err:
                raise Exception(f"JSON from websocket server incorrect / {err}")

            if isinstance(res, dict):
                if res.get("act", "") == "error":
                    raise Exception(f"Order failed: {res.get('data', '')}")
                elif res.get("act", "") == "go_away":
                    raise Exception(f"Order failed")

            try:
                ws.close()
            except Exception:
                return

    @classmethod
    def get_order_id(cls, page, order_time, action, _type, pair, price, amount):
        order_id = None
        orders = cls.rgx["orders"].findall(page)
        order_time = order_time.strftime("%d/%m/%Y %H:%M:%S")
        for order in orders:
            order_details = cls.rgx["order_details"].findall(order)
            if all(
                [
                    order_time == order_details[0].strip(),
                    f"{action} / {_type}" == order_details[1].strip(),
                    pair == re.sub("<[^>]+>", "", order_details[2].strip()),
                    amount == order_details[3].strip(),
                    price == order_details[4].strip(),
                ]
            ):
                order_id = match_or_empty(cls.rgx["order_id"], order)
        return order_id

    @classmethod
    def was_order_paid(cls, order_time, action, _type, pair, price, amount):
        s = rq.Session()

        orders_page = cls.get_response(cls.orders_page, s)
        if not orders_page:
            cls.login()
            orders_page = cls.get_response(cls.orders_page, s)
            if not orders_page:
                raise Exception("Check order status failed: connection problems")

        page = orders_page.text
        if not cls.get_order_id(page, order_time, action, _type, pair, price, amount):
            return True
        else:
            return False

    @classmethod
    def get_close_order_data(cls, page, order_time, action, _type, pair, price, amount):
        headers = deepcopy(cls.headers)
        headers["Cookie"] = cls.full_cookies
        headers["Referer"] = "https://site.com/orders"
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        _id = cls.get_order_id(page, order_time, action, _type, pair, price, amount)
        data = {
            "_csrf": cls.get_csrf_token(page),
            "id": _id,
        }

        return (headers, data)

    @classmethod
    def close_order(cls, order_time, action, _type, pair, price, amount):
        s = rq.Session()

        orders_page = cls.get_response(cls.orders_page, s)
        if not orders_page:
            cls.login()
            orders_page = cls.get_response(cls.orders_page, s)
            if not orders_page:
                raise Exception("Close order failed: connection problems")

        headers, data = cls.get_close_order_data(
            orders_page.text, order_time, action, _type, pair, price, amount
        )
        res = cls.get_response(cls.close_order_url, s, "post", headers, data)
        if not res:
            raise Exception("Close order failed: connection problems")

        if res.text != "ok":
            raise Exception(f"Close order failed: {res.text}")
        else:
            return True
