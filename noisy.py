import argparse
import datetime
import json
import logging
from logging import config as logging_config
import random
import re
import sys
from threading import Thread
import time

import paramiko
import paramiko.client
from requests import get
import requests
from urllib3.exceptions import LocationParseError
from sched2 import scheduler

try:                 # Python 2
    from urllib.parse import urljoin, urlparse
except ImportError:  # Python 3
    from urlparse import urljoin, urlparse

try:                 # Python 2
    reload( sys )
    sys.setdefaultencoding('latin-1')
except NameError:    # Python 3
    pass

DEFAULT_LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s - [%(module)s:%(levelname)s] [%(filename)s:%(lineno)d] - %(message)s"
        },
        "root": {
            "format": "ROOT - %(asctime)s - [%(module)s:%(levelname)s] [%(filename)s:%(lineno)d] - %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default"
        },
        "root_console": {
            "class": "logging.StreamHandler",
            "formatter": "root"
        },
        "file":{
            "formatter":"default",
            "class":"logging.FileHandler",
            "level":"INFO",
            "filename":"noisy.log"
        }        
    },
    "loggers": {
        "app": {
            "handlers": ["console"],
            "level": "INFO",
            # Don't send it up my namespace for additional handling
            "propagate": False
        }
    },
    "root": {
        "handlers": ["root_console","file"],
        "level": "INFO"
    }
}

logging_config.dictConfig(DEFAULT_LOGGING_CONFIG)

sc               = scheduler()
CRAWLER_INSTANCE = None

def generate_random_number():
    return random.randint(1000000000, 9999999999)

@sc.every( 90 )
def check_for_updated_config( ):
    global CRAWLER_INSTANCE
    logging.info( 'checking for updated configuration' )

    CRAWLER_INSTANCE.update_configuration( )

SSH_LINUX_COMMANDS =    [
                            'ps -ef',
                            'lsmod',
                            'lsusb',
                            'whoami',
                            'pwd',
                            'netstat -ano',
                            'ip a',
                            'route',
                            'arp -a',
                            'who',
                            'sysctl -a',
                            'last',
                            'uptime',
                            'mount',
                            'lsof',
                            'lsb_release -a',
                            'date',
                            'dpkg -l',
                        ]

SSH_LINUX_ROOT_COMMANDS =   [
                                'lvdisplay',
                            ]

class Crawler:
    def __init__( self ):
        """
        Initializes the Crawl class
        """
        self._config     = {}
        self.serial      = 0
        self.last_serial = 0
        self._links      = []
        self._start_time = None
        self.path_to_conf= 'config.json'

    class CrawlerTimedOut( Exception ):
        """
        Raised when the specified timeout is exceeded
        """
        pass

    def update_configuration( self ):
        logging.info( 'checking configuration' )
        
        new_configuration = self.__load_config_file__( self.path_to_conf )
        if new_configuration:
            new_serial = new_configuration['serial']
            if self.serial != new_serial:
                logging.info( 'WOAH, updated configuration!' )
                self.last_serial = self.serial
                self.serial = new_serial
                self._config = new_configuration

    def _request( self, url ):
        """
        Sends a POST/GET requests using a random user agent
        :param url: the url to visit
        :return: the response Requests object
        """
        random_user_agent = random.choice(self._config["user_agents"])
        headers = {'user-agent': random_user_agent}

        response = requests.get(url, headers=headers, timeout=5)

        return response

    @staticmethod
    def _normalize_link( link, root_url ):
        """
        Normalizes links extracted from the DOM by making them all absolute, so
        we can request them, for example, turns a "/images" link extracted from https://imgur.com
        to "https://imgur.com/images"
        :param link: link found in the DOM
        :param root_url: the URL the DOM was loaded from
        :return: absolute link
        """
        try:
            parsed_url = urlparse(link)
        except ValueError:
            # urlparse can get confused about urls with the ']'
            # character and thinks it must be a malformed IPv6 URL
            return None
        parsed_root_url = urlparse(root_url)

        # '//' means keep the current protocol used to access this URL
        if link.startswith("//"):
            return "{}://{}{}".format(parsed_root_url.scheme, parsed_url.netloc, parsed_url.path)

        # possibly a relative path
        if not parsed_url.scheme:
            return urljoin(root_url, link)

        return link

    @staticmethod
    def _is_valid_url( url ):
        """
        Check if a url is a valid url.
        Used to filter out invalid values that were found in the "href" attribute,
        for example "javascript:void(0)"
        taken from https://stackoverflow.com/questions/7160737
        :param url: url to be checked
        :return: boolean indicating whether the URL is valid or not
        """
        regex = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return re.match(regex, url) is not None

    def connect_via_ssh( self, host, username, password ) -> paramiko.client.SSHClient:
        client = None
        logging.info( 'connect to host {} via SSH as {}'.format(host, username) ) 
        try:
            client = paramiko.client.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect( host, username=username, password=password )
        except:
            logging.error( 'failed to connect to {}'.format(client) )
        
        return client
    
    def execute_sudo_command( self, ssh_client, command, password ):
        """Executes a command with sudo on the remote host."""

        # Open a new channel
        channel = ssh_client.get_transport().open_session()
        channel.get_pty()
        channel.invoke_shell()

        # Send the command with sudo
        channel.send('sudo ' + command + '\n')

        # If sudo requires a password, provide it here
        channel.send( '{}\n'.format(password) )

        # Read the output
        output = ""
        while True:
            if channel.recv_ready():
                output += channel.recv(1024).decode('utf-8')
            else:
                break

        # Close the channel
        channel.close()
        return output

    # https://www.linode.com/docs/guides/use-paramiko-python-to-ssh-into-a-server/
    def execute_random_commands_via_ssh( self, host_entry ):
        parts = host_entry.split("|")
        uh    = parts[0]
        passw = parts[1]
        
        username_parts = uh.split("@")
        username       = username_parts[0]
        host           = username_parts[1]
        
        logging.info( 'starting random SSH traffic' )
        
        active_ssh_client = self.connect_via_ssh( host, username, passw )
        if active_ssh_client:
            logging.info( 'ok, beautiful, connected to {}'.format(host) )
            number_of_commands = random.randint( 1, self._config['local']['size'] )
            for c in range( number_of_commands ):
                logging.info( 'execute a random command now' )
                use_userland_command = bool(random.getrandbits(1))
                if use_userland_command:
                    random_command = random.choice( SSH_LINUX_COMMANDS ) 
                    stdin, stdout, stderr = active_ssh_client.exec_command( random_command )
                else:
                    random_command = random.choice( SSH_LINUX_ROOT_COMMANDS )
                    self.execute_sudo_command( active_ssh_client, random_command, passw )
                logging.debug( 'executed {}'.format(random_command) )
                time.sleep( random.randint(5,20) )
            
            logging.info( 'ok, closing SSH connection' )
            active_ssh_client.close( )
        
        logging.info( 'finished random SSH traffic' )
          
    def perform_random_ssh_action( self ):
        logging.info( 'ok, lets randomly SSH to a host now' )                
        h = random.choice( self._config['local']['ssh'] )
        logging.info( 'chose {}'.format(h) )
        self.execute_random_commands_via_ssh( h )
        
    def _is_blacklisted( self, url ):
        """
        Checks is a URL is blacklisted
        :param url: full URL
        :return: boolean indicating whether a URL is blacklisted or not
        """
        return any(blacklisted_url in url for blacklisted_url in self._config["blacklisted_urls"])

    def _should_accept_url( self, url ):
        """
        filters url if it is blacklisted or not valid, we put filtering logic here
        :param url: full url to be checked
        :return: boolean of whether or not the url should be accepted and potentially visited
        """
        return url and self._is_valid_url(url) and not self._is_blacklisted(url)

    def _extract_urls( self, body, root_url ):
        """
        gathers links to be visited in the future from a web page's body.
        does it by finding "href" attributes in the DOM
        :param body: the HTML body to extract links from
        :param root_url: the root URL of the given body
        :return: list of extracted links
        """
        pattern = r"href=[\"'](?!#)(.*?)[\"'].*?"  # ignore links starting with #, no point in re-visiting the same page
        urls = re.findall(pattern, str(body))

        normalize_urls = [self._normalize_link(url, root_url) for url in urls]
        filtered_urls = list(filter(self._should_accept_url, normalize_urls))

        return filtered_urls

    def _remove_and_blacklist( self, link ):
        """
        Removes a link from our current links list
        and blacklists it so we don't visit it in the future
        :param link: link to remove and blacklist
        """
        self._config['blacklisted_urls'].append(link)
        del self._links[self._links.index(link)]

    def _browse_from_links( self, depth=0 ):
        """
        Selects a random link out of the available link list and visits it.
        Blacklists any link that is not responsive or that contains no other links.
        Please note that this function is recursive and will keep calling itself until
        a dead end has reached or when we ran out of links
        :param depth: our current link depth
        """
        is_depth_reached = depth >= self._config['max_depth']
        if not len(self._links) or is_depth_reached:
            logging.debug("Hit a dead end, moving to the next root URL")
            # escape from the recursion, we don't have links to continue or we have reached the max depth
            return

        if self._is_timeout_reached():
            raise self.CrawlerTimedOut

        random_link = random.choice( self._links )
        try:
            logging.info("Visiting {}".format(random_link))
            sub_page = self._request(random_link).content
            sub_links = self._extract_urls(sub_page, random_link)

            # sleep for a random amount of time
            time.sleep(random.randrange(self._config["min_sleep"], self._config["max_sleep"]))

            # make sure we have more than 1 link to pick from
            if len(sub_links) > 1:
                # extract links from the new page
                self._links = self._extract_urls(sub_page, random_link)
            else:
                # else retry with current link list
                # remove the dead-end link from our list
                self._remove_and_blacklist(random_link)

        except requests.exceptions.RequestException:
            logging.debug("Exception on URL: %s, removing from list and trying again!" % random_link)
            self._remove_and_blacklist(random_link)

        self._browse_from_links(depth + 1)

    def __load_config_file__( self, path ):
        with open( path, 'r' ) as config_file:
            config = json.load(config_file)
            return config
        return None

    def save_config_file( self ):
        with open( self.path_to_conf, 'w' ) as writer:
            writer.write( json.dumps(self._config, indent=4, sort_keys=True) )
    
    def load_config_file( self, file_path ):
        """
        Loads and decodes a JSON config file, sets the config of the crawler instance
        to the loaded one
        :param file_path: path of the config file
        :return:
        """
        self.path_to_conf = file_path
        self.set_config( self.__load_config_file__(file_path) )
        
        if self.serial != 0:
            self.last_serial = self.serial
            
        logging.info( 'setting serial for the first time this launch' )
        if 'serial' in self._config:
            self.serial = self._config['serial']
            self.last_serial = self.serial
        else:
            logging.info( 'setting initial serial number to random value' )
            self.serial = generate_random_number( )
            self._config['serial'] = self.serial
            self.save_config_file( )
            
    def set_config( self, config ):
        """
        Sets the config of the crawler instance to the provided dict
        :param config: dict of configuration options, for example:
        {
            "root_urls": [],
            "blacklisted_urls": [],
            "click_depth": 5
            ...
        }
        """
        self._config = config

    def set_option( self, option, value ):
        """
        Sets a specific key in the config dict
        :param option: the option key in the config, for example: "max_depth"
        :param value: value for the option
        """
        self._config[option] = value

    def _is_timeout_reached( self ):
        """
        Determines whether the specified timeout has reached, if no timeout
        is specified then return false
        :return: boolean indicating whether the timeout has reached
        """
        is_timeout_set = self._config["timeout"] is not False  # False is set when no timeout is desired
        end_time       = self._start_time + datetime.timedelta(seconds=self._config["timeout"])
        is_timed_out   = datetime.datetime.now() >= end_time

        return is_timeout_set and is_timed_out

    def start_scheduler( self ):
        logging.info( 'starting scheduler' )
        sc.run( )
        while True:
            time.sleep( 5 )

    def crawl( self ):
        """
        Collects links from our root urls, stores them and then calls
        `_browse_from_links` to browse them
        """
        self._start_time = datetime.datetime.now()
        logging.info( 'starting activity...' )
        
        self.daemon = Thread(target=self.start_scheduler, daemon=True, name='Monitor Scheduler')
        self.daemon.start( )
        
        while True:
            if not self._config['offline']:
                logging.info( 'we have not been forced offline, choose a random link to visit' )
                url = random.choice(self._config["root_urls"])
                try:
                    body = self._request(url).content
                    self._links = self._extract_urls(body, url)
                    logging.debug("found {} links".format(len(self._links)))
                    self._browse_from_links()

                except requests.exceptions.RequestException:
                    logging.warning("Error connecting to root url: {}".format(url))
                    
                except MemoryError:
                    logging.warning("Error: content at url: {} is exhausting the memory".format(url))

                except LocationParseError:
                    logging.warning("Error encountered during parsing of: {}".format(url))

                except self.CrawlerTimedOut:
                    logging.info("Timeout has exceeded, exiting")
                    return
            else:
                time.sleep( random.randint(5,30) )
                self.perform_random_ssh_action( )
                
def lookup_my_public_ipaddress( url='http://ipinfo.io/json' ):
    data         = None
    try:
        logging.info( 'attempt to lookup public facing Internet details. this is a check to see if we are online' )
        response = get(url)
        data     = response.json()
        logging.info( 'found public details, we ARE connected to the Internet!' )
    except:
        logging.warning( 'no response found, are you connected to the internet?' )
    return data

def main( ):
    global CRAWLER_INSTANCE
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', metavar='-l', type=str, help='logging level', default='info')
    parser.add_argument('--offline', action=argparse.BooleanOptionalAction, help='Force Noisy to generate offline traffic only' )
    parser.add_argument('--debug', action=argparse.BooleanOptionalAction, help='Force Noisy to generate offline traffic only' )

    parser.add_argument('--config', metavar='-c', required=True, type=str, help='config file')
    parser.add_argument('--timeout', metavar='-t', required=False, type=int,
                        help='for how long the crawler should be running, in seconds', default=False)
    args  = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel( logging.DEBUG )

    internet_details = lookup_my_public_ipaddress( )
    if not internet_details:
        args.offline = True

    level = getattr(logging, args.log.upper())
    logging.basicConfig(level=level)

    crawler = Crawler()
    crawler.load_config_file( args.config )

    if args.offline:
        logging.info( 'forcing Noisy offline, this will ignore all hosts in configuration!' )
        crawler.set_option( 'offline', True )

    if args.timeout:
        crawler.set_option( 'timeout', args.timeout )

    CRAWLER_INSTANCE = crawler
    CRAWLER_INSTANCE.crawl( )


if __name__ == '__main__':
    main()
