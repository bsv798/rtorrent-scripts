#!/usr/bin/env python3

from rss_config import rss_list_config

import base64
import html
import http.cookiejar
import logging
import os
import pathlib
import re
import shutil
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree

RSS_HOME_PATH = os.path.join(os.path.expanduser('~'), 'rss')
RSS_COOKIES_PATH = os.path.join(RSS_HOME_PATH, 'cookies.txt')
RSS_LOGS_PATH = os.path.join(RSS_HOME_PATH, 'rss.log')
RSS_NAMES_PATH = os.path.join('/srv/www/rss', 'names.txt')

ROOT_LOGGER = None


def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    ROOT_LOGGER.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))


def prepare_logger():
    root_logger = logging.getLogger()
    log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")

    file_handler = logging.FileHandler(RSS_LOGS_PATH)

    file_handler.setFormatter(log_formatter)
    root_logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()

    console_handler.setFormatter(log_formatter)
    root_logger.addHandler(console_handler)

    root_logger.setLevel(logging.DEBUG)

    sys.excepthook = handle_exception

    return root_logger


def save_cookies(url, login, password):
    data = urllib.parse.urlencode({'username': login, 'password': password, 'returnto': '/'}).encode('utf-8')
    request, file_cookie_jar = prepare_authorized_request(url, data)

    with urllib.request.urlopen(request) as response:
        file_cookie_jar.extract_cookies(response, request)
        file_cookie_jar.save(ignore_discard=True, ignore_expires=True)
        ROOT_LOGGER.debug('Got cookies: %s', file_cookie_jar)


def prepare_authorized_request(url, data, method=None):
    headers = {'Content-Type': 'application/x-www-form-urlencoded',
               'User-agent': 'Mozilla/5.0 Chrome/81.0.4044.92'}
    request = urllib.request.Request(url, data, headers, method=method)
    parsed_url = urllib.parse.urlparse(url)
    cookie_policy = http.cookiejar.DefaultCookiePolicy(allowed_domains=[parsed_url.hostname])
    file_cookie_jar = http.cookiejar.MozillaCookieJar(RSS_COOKIES_PATH, policy=cookie_policy)
    cookie_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(file_cookie_jar))
    urllib.request.install_opener(cookie_opener)
    file_cookie_jar.load()

    return request, file_cookie_jar


def get_rss_xml(rss_url):
    request, file_cookie_jar = prepare_authorized_request(rss_url, None)

    with urllib.request.urlopen(request) as response:
        html_text = response.read()
        rss_encoding = re.search(b'<\\?xml version=".+" encoding="(.+)" \\?>', html_text).group(1).decode('ascii')
        # rss_text = html.unescape(html_text.decode(rss_encoding))
        # rss_text = html.unescape(rss_text)
        ROOT_LOGGER.debug('Got rss %s from url %s', html_text.decode(rss_encoding), rss_url)
        rss_xml = xml.etree.ElementTree.fromstring(html_text)

        return rss_xml


def get_rss_list(rss_xml):
    rss_list = []
    date_regexp = re.compile('^.*(Added|Добавлен): (\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}).*$', re.MULTILINE)

    for rss_item in rss_xml.findall('./channel/item'):
        rss_title = html.unescape(rss_item.find('./title').text)
        rss_date = date_regexp.search(rss_item.find('./description').text).group(2)
        url = urllib.parse.urlparse(rss_item.find('./link').text)
        query = urllib.parse.parse_qs(url.query)
        encoded_query = urllib.parse.urlencode(query, doseq=True)
        rss_url = f'{url.scheme}://{url.hostname}{url.path}?{encoded_query}'
        rss_title_hash = base64.b64encode(f'{rss_title} {rss_date}'.encode('utf-8'), b'+-').decode('ascii')
        rss_dict = {'url': rss_url, 'title': rss_title, 'date': rss_date, 'title_hash': rss_title_hash}

        ROOT_LOGGER.debug('Got rss dict: %s', rss_dict)
        rss_list.append(rss_dict)

    return rss_list


def get_filtered_map(rss_list, title_filters):
    filtered_list = []

    for title_filter in title_filters:
        regexp = re.compile(title_filter)

        for item in rss_list:
            rss_title = item['title']

            if regexp.match(rss_title):
                ROOT_LOGGER.debug('Filter %s match title %s', regexp, rss_title)
                filtered_list.append(item)
            else:
                ROOT_LOGGER.debug('Filter %s doesn''t match title %s', regexp, rss_title)

    return filtered_list


def download_torrents(rss_list, base_torrent_path):
    title_hash_base_path = os.path.join(base_torrent_path, '.title_hash')

    os.makedirs(base_torrent_path, exist_ok=True)
    os.makedirs(title_hash_base_path, exist_ok=True)

    for item in rss_list:
        title_hash_path = os.path.join(title_hash_base_path, item['title_hash'])

        if not os.path.isfile(title_hash_path):
            rss_url = item['url']
            torrent_name = get_torrent_name(rss_url)
            torrent_path = os.path.join(base_torrent_path, torrent_name)

            if not os.path.isfile(torrent_path):
                download_torrent(torrent_path, item['title'], rss_url)
                pathlib.Path(title_hash_path).touch()
                update_names_file(torrent_name, item['title'])


def get_torrent_name(rss_url):
    request, file_cookie_jar = prepare_authorized_request(rss_url, None, 'HEAD')

    with urllib.request.urlopen(request) as response:
        rss_header = re.split(';[ ]?', response.getheader('Content-Disposition'))
        torrent_name = next(x for x in rss_header if x.startswith('filename'))[9:].strip('\"')
        ROOT_LOGGER.debug('Got torrent name %s from url %s', torrent_name, rss_url)

    return torrent_name


def download_torrent(torrent_path, rss_title, rss_url):
    request, file_cookie_jar = prepare_authorized_request(rss_url, None)

    with urllib.request.urlopen(request) as response, open(torrent_path, 'wb') as out_file:
        shutil.copyfileobj(response, out_file)
        ROOT_LOGGER.info('Downloaded torrent %s from url %s to path %s', rss_title, rss_url, torrent_path)


def update_names_file(torrent_name, title):
    names = []

    if os.path.isfile(RSS_NAMES_PATH):
        with open(RSS_NAMES_PATH, 'r') as in_file:
            names = in_file.readlines()

    names.append(f'{torrent_name} - {title}{os.linesep}')
    names.sort()

    with open(RSS_NAMES_PATH, 'w') as out_file:
        out_file.writelines(names)


ROOT_LOGGER = prepare_logger()

for item in rss_list_config:
    ROOT_LOGGER.info('Start rss acquisition for %s', item['name'])

    rss_xml = get_rss_xml(item['url'])
    rss_list = get_rss_list(rss_xml)
    rss_list = get_filtered_map(rss_list, item['filters'])

    download_torrents(rss_list, item['dir'])

    ROOT_LOGGER.info('End rss acquisition for %s', item['name'])
