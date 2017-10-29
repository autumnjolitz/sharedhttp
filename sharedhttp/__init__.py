import asyncio
import functools
import hashlib
import ipaddress
import itertools
import logging
import os
import secrets
import socket
import struct
import time
from enum import Enum, IntEnum

import msgpack
from sanic import Sanic, response, Blueprint
from sanic.request import Request as _Request
from sanic_jinja2 import SanicJinja2

from .about import __version__


__version__  # Silence unused import warning.


try:
    import uvloop
except ImportError:
    uvloop = None

try:
    from ujson import loads as json_loads
except ImportError:
    from json import loads as json_loads

logger = logging.getLogger(__name__)

SUPPORTS_REUSEABLE_SOCKET = hasattr(socket, 'SO_REUSEPORT')
DEFAULT_HTTP_INET = ipaddress.IPv4Address(0)  # 0.0.0.0
DEFAULT_GOSSIP_INET = ipaddress.IPv4Address('224.0.0.251')  # multicast


class States(Enum):
    UNINITIALIZED = 0
    INITIALIZED = 1
    ANNOUNCING = 2
    REBUILDING = 3
    WAITING = 4

CLASS_LOOKUP = {}


def register_msgpack(cls):
    assert isinstance(cls, type)
    CLASS_LOOKUP[cls.__name__.encode('ascii')] = cls
    return cls


def load_data(item):
    if isinstance(item, (list, tuple)) and len(item) > 2:
        class_name, *data, checksum = item
        return CLASS_LOOKUP[class_name].from_msgpack(data, checksum)
    return item


class NodeFlags(IntEnum):
    INITIALIZED = 1
    CHECKING_ROUTE = 2


@register_msgpack
class NodeInfo:
    __slots__ = ('host', 'port', 'random_seed', 'routeable', '_flags')

    async def check_routeable(self, loop):
        if self._flags & NodeFlags.CHECKING_ROUTE == NodeFlags.CHECKING_ROUTE:
            logger.debug(f'Asked to check routeability of {self!s} but already checking it!')

        self._flags |= NodeFlags.CHECKING_ROUTE

        logger.debug(f'Asked to check routeability of {self!s}')
        future = asyncio.open_connection(host=str(self.host), port=self.port)
        try:
            reader, writer = await asyncio.wait_for(future, timeout=5)
        except asyncio.TimeoutError:
            logger.warn(f'Unable to contact {self.host}:{self.port}')
            self.routeable = False
            return False
        else:
            writer.write(b'GET /version HTTP/1.1\r\n')
            writer.write(b'Host: %s\r\n' % (str(self.host).encode('ascii'),))
            writer.write(b'Connection: close\r\n\r\n')
            await writer.drain()
            data = await reader.read(-1)
            _, data = data.split(b'\r\n\r\n')
            try:
                data = json_loads(data)
            except ValueError:
                logger.warn(f'{self.host} returned non JSON payload {data}. Disabling!')
                self.routeable = False
                return False
            logger.debug(f'{self.host.exploded}:{self.port} -> {data}')
            writer.close()
            self.routeable = True
        finally:
            self._flags ^= self._flags & NodeFlags.CHECKING_ROUTE
        return True

    def __init__(self, host, port, random_seed, routeable):
        assert isinstance(host, ipaddress.IPv4Address)
        assert isinstance(random_seed, bytes) and len(random_seed) == 128
        assert isinstance(routeable, bool)

        self.host = host
        self.port = port
        self.random_seed = random_seed
        self.routeable = routeable
        self._flags = NodeFlags.INITIALIZED

    def __repr__(self):
        return f'{self.__class__.__name__}({self.host!r}, {self.port!r}, ' \
            f'{self.random_seed!r}, {self.routeable!r})'

    def __str__(self):
        return f'{self.__class__.__name__}<{self.host!s}:{self.port}, {self.routeable}>'

    def checksum(self):
        hasher = hashlib.sha256()
        hasher.update(self.__class__.__name__.encode('ascii'))
        hasher.update(self.host.packed)
        hasher.update(self.random_seed)
        hasher.update(b'1' if self.routeable else b'0')
        return hasher.hexdigest().encode('ascii')

    def to_msgpack(self):
        return msgpack.packb(
            [self.__class__.__name__, self.host.packed,
             self.port,
             self.random_seed, self.routeable, self.checksum()])

    @classmethod
    def from_msgpack(cls, data, checksum):
        ip, port, seed, routeable = data
        item = cls(ipaddress.IPv4Address(ip), port, seed, routeable)
        assert item.checksum() == checksum, \
            f'{item.checksum().encode("ascii")} != {checksum.encode("ascii")}'
        return item


http_routes = Blueprint(__name__)


def get_ip():
    '''
    Get primary routeable ip,
    From: https://stackoverflow.com/a/28950776/367120
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


@http_routes.route('/version')
async def check_version(request):
    return response.json({'name': 'sharedhttp', 'version': __version__})


@http_routes.route('/')
async def list_info(request):
    primary_ip = get_ip()
    logger.info(f'Me: {request.server.node_info!r}')
    logger.info(f'Them: {request.server.nodes.nodes}')
    return await request.render_async(
        'index.html', nodes=request.server.nodes, root=request.share_root,
        server=request.server, primary_hostname=socket.gethostname(),
        primary_ip=primary_ip)


@http_routes.route('/shared/')
@http_routes.route('/shared/<path:[^/].*?>')
async def handle_files(request, path=None):
    if path is None:
        path = '.'
    path = os.path.join(request.share_root, path)
    if not path.startswith(request.share_root):
        logger.critical(
            f'{request.ip} tried to access {path} but it violated root {request.share_root}!')
        return response.json(
            {'error': 'IllegalTraversal', 'message': 'You may not escape this root.'},
            status=404)

    if os.path.isdir(path):
        return await request.render_async(
            'listing.html', files=[item for item in os.scandir(path)],
            current_path=path[len(request.share_root)+1:])
    return await response.file_stream(path)


class TTL:
    def __init__(self, val=None, max_ttl=-1):
        self.start = val or time.time()
        self.max_ttl = max_ttl

    def refresh(self):
        self.start = time.time()
        return self

    @property
    def age(self):
        return time.time() - self.start

    @property
    def age_readable(self):
        seconds = int(self.age)
        minutes, seconds = divmod(seconds, 60)
        if not minutes:
            return f'{seconds} seconds'
        hours, minutes = divmod(minutes, 60)
        if not hours:
            return f'{minutes} minutes and {seconds} seconds'
        return f'{hours} hours'

    @property
    def expired(self):
        if self.max_ttl == -1:
            return False
        return time.time() - self.start > self.max_ttl

    def __sub__(self, other):
        return self.start - other

    def __add__(self, other):
        return self.start + other

    def __rsub__(self, prior):
        return prior - self.start

    def __radd__(self, prior):
        return prior + self.start


class NodeManager:
    def __init__(self):
        self.nodes = {}    # mapping of secret -> NodeInfo
        self.ips = {}      # mapping of ip -> timestamp
        self.secret_ips = {}  # mapping of secret to ips

    async def update(self, item, loop):
        assert isinstance(item, NodeInfo)
        assert int(item.host), f'{item} lacks a non-zero host address!'
        logger.debug('Update with {item!s}')
        await item.check_routeable(loop)

        if item.random_seed not in self.nodes:
            # New node!
            self.nodes[item.random_seed] = item
            # if we don't hear from it in 5 mins, it's dead
            self.ips[str(item.host)] = TTL(max_ttl=5*60)
            self.secret_ips[item.random_seed] = [str(item.host)]  # make copy of ip.
            return
        # We've seen you before. Do you have a new ip? Is the old one reachable?
        ips = self.secret_ips[item.random_seed]
        if str(item.host) in self.ips:
            # Same old ip?
            ttl = self.ips[str(item.host)]
            ttl.start = time.time()
        else:
            self.ips[str(item.host)] = TTL(max_ttl=5*60)
            ips.append((str(item.host)))
        for index, ip, ttl in (
                (index, ips[index], self.ips[ips[index]]) for index in range(len(ips)-1, -1, -1)):
            if ttl.expired:
                del self.ips[ip]
                del ips[index]
        if not ips:
            del self.nodes[item.random_seed]
            assert item.random_seed not in self.nodes
            assert item.host.exploded not in self.ips
            assert item.random_seed not in self.secret_ips
            logger.warn('Node {item!s} was removed due to no ips')
            return
        now = time.time()
        best_ip = min(ips, key=lambda obj: now - self.ips[obj])
        if best_ip != item.host.exploded:
            logger.info(f'Switching {item!r} from {item.host!s} -> {best_ip}')
            item.host = ipaddress.IPv4Address(best_ip)

    async def refresh(self, loop):
        futures = {}
        lost_nodes = not self.nodes
        for secret in tuple(self.nodes.keys()):
            node = self.nodes[secret]
            ips = self.secret_ips[secret]
            if not node.routeable:
                future = node.check_routeable(loop)
                futures[future] = secret
                continue
            for index in range(-1, -len(ips)-1, -1):
                ip = ips[index]
                ttl = self.ips[ip]
                if ttl.expired:
                    del ips[index]
                    del self.ips[ip]

            if not self.secret_ips[secret]:
                logger.debug(f'Forgetting about {node}')
                del self.nodes[secret]
                del self.secret_ips[secret]
                lost_nodes = True
        if futures:
            results, _ = await asyncio.wait(futures)
            for future in results:
                secret = futures[future]
                result = future.result()
                node = self.nodes[secret]
                if not result:
                    logger.debug(f'{node} is not routeable despite checks. Removing.')
                    del self.nodes[secret]
                    ips = self.secret_ips.pop(secret)
                    for ip in ips:
                        del self.ips[ip]
                    lost_nodes = True
                    continue
                logger.debug(f'{node} is live.')
                assert node.routeable
        return lost_nodes

    def __iter__(self):
        for secret in self.nodes:
            ips = self.secret_ips[secret]
            yield self.nodes[secret], {ip: self.ips[ip] for ip in ips}


class Request(_Request):
    __slots__ = ('render_async', 'share_root', 'server')


class GossipServer:
    def __init__(self, root, loop):
        self.root = os.path.abspath(root)
        self.loop = loop
        self.state = States.UNINITIALIZED
        # Mapping of addr -> NodeInfo
        self.nodes = NodeManager()

        self.node_info = NodeInfo(ipaddress.IPv4Address(0), None, secrets.token_bytes(128), True)

        self.app = Sanic(__name__, request_class=Request)

        self.jinja = SanicJinja2(enable_async=True)

        @self.app.middleware('request')
        async def add_jinja_to_request(request):
            request.render_async = functools.partial(self.jinja.render_async, request=request)
            request.share_root = root
            request.server = self

        self.jinja.init_app(self.app, pkg_name=__name__)

        self.app.blueprint(http_routes)

    @property
    def http_port(self):
        return self.node_info.port

    @http_port.setter
    def http_port(self, val):
        assert isinstance(val, int) and 1024 < val < 65535, f'{val} must be between 1024 and 65535'
        self.node_info.port = val

    async def start(self):
        assert self.state == States.UNINITIALIZED
        self.broadcast_transport, self.broadcaster = await self.loop.create_datagram_endpoint(
            lambda: GossipBroadcaster(self), None, sock=self.gossip_broadcast_socket)
        self.listener_transport, self.listener = await self.loop.create_datagram_endpoint(
            lambda: GossipListener(self), None, sock=self.gossip_recv_socket)

        self.state = States.INITIALIZED

        await self.heartbeat()
        self.http_server = await self.app.create_server(sock=self.http_socket)

    async def heartbeat(self):
        logger.debug('heartbeat called!')
        if self.state == States.INITIALIZED:
            self.state = States.ANNOUNCING
            self.broadcast_message(self.node_info.to_msgpack())
            self.state = States.WAITING
            await asyncio.sleep(5)
            asyncio.ensure_future(self.heartbeat(), loop=self.loop)
            return

        self.broadcast_message(f'heartbeat{self.node_info.random_seed}')
        if (await self.nodes.refresh(self.loop)):
            self.state = States.REBUILDING

        if self.state == States.REBUILDING:
            self.broadcast_message(self.node_info.to_msgpack())
            self.state = States.WAITING

        await asyncio.sleep(5)
        asyncio.ensure_future(self.heartbeat(), loop=self.loop)

    def broadcast_message(self, data):
        if not isinstance(data, bytes):
            if hasattr(data, 'to_msgpack'):
                data = data.to_msgpack()
            elif isinstance(data, str):
                data = msgpack.packb(data)
            else:
                raise TypeError('data must be bytes or implement to_msgpack')
        self.broadcast_transport.sendto(data, (DEFAULT_GOSSIP_INET.exploded, self.gossip_port))

    def on_remote_response(self, data, addr):
        '''
        This handles when we broadcast to others and want to handle their response
        '''
        logger.debug(f'{addr} responded to inquiry with {data!r}')
        remote_ip, _ = addr
        if data == b'Ok':
            if addr not in self.nodes.ips:
                # I don't recognize this node. It should identify itself.
                self.broadcast_transport.sendto(
                    b'WhoAreYou?', (remote_ip, self.gossip_port+1))
                return
        elif data == b'WhoAreYou?':
            response = self.node_info.to_msgpack()
            response = b'IAMA%i.%s' % (len(response), response)
            self.broadcast_transport.sendto(response, (remote_ip, self.gossip_port+1))
        elif data.startswith(b'IAMA'):
            data = data[len(b'IAMA'):]
            length, data = data.split('.', 1)
            if len(data) != length:
                logger.warn(f'Corrupted data from {remote_ip}')
                return
            try:
                data = msgpack.unpackb(data)
                data = load_data(data)
            except Exception:
                logger.exception(f'Unable to parse IAMA from {remote_ip}')
                return
            assert isinstance(data, NodeInfo)
            data.host = remote_ip
            asyncio.ensure_future(self.nodes.update(data, self.loop))

    def on_remote_request(self, data, addr):
        '''
        Serve a response to a query
        '''
        remote_ip, _ = addr
        try:
            data = msgpack.unpackb(data)
            data = load_data(data)
        except Exception:
            logger.exception(f'Unable to unpack {data!r}')
            return
        if isinstance(data, NodeInfo):
            if data.random_seed == self.node_info.random_seed:
                # It's us. Disgard.
                return
            data.host = ipaddress.IPv4Address(remote_ip)
            logger.debug(f'[NodeInfo] Heard from a stranger at {remote_ip} -> {data!r}!')
            asyncio.ensure_future(self.nodes.update(data, self.loop))

            logger.debug(f'Send ok to {remote_ip}:{self.gossip_port}')
            # Todo: Use this as a way to sync state?
            self.broadcast_transport.sendto(b'Ok', (remote_ip, self.gossip_port+1))
            return
        if data.startswith(b'heartbeat'):
            secret = data[len(b'heartbeat')+1:]
            if secret == self.node_info.random_seed:
                logger.debug(f'[Beat] Heard back from ourselves {data!r}')
                return
            if secret not in self.nodes:
                # logger.debug(f'Unknown client {remote_ip} presents {secret}')
                return
            if remote_ip in self.nodes.ips:
                self.nodes.ips[remote_ip].refresh()
            else:
                logger.error(f'{remote_ip} is unknown but secret {secret} belongs to {self.nodes.nodes[secret]}')
            return
        logger.debug(f'Disregarding {data!r}')

    def close(self):
        if self.broadcast_transport:
            self.broadcast_transport.close()
        if self.listener_transport:
            self.listener_transport.close()
        self.broadcaster = self.listener = None
        self.broadcast_transport = self.listener_transport = None
        self.gossip_recv_socket.close()
        self.gossip_broadcast_socket.close()
        self.http_socket.close()
        self.gossip_recv_socket = None
        self.gossip_broadcast_socket = None
        self.http_socket = None

    async def bind(self, ip, http_port, gossip_port, max_http_backlog=100):
        self.http_port = http_port
        self.gossip_port = gossip_port

        self.gossip_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if SUPPORTS_REUSEABLE_SOCKET:
            self.gossip_recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.gossip_recv_socket.bind((ip, gossip_port))

        multicast_request = struct.pack('4sL', DEFAULT_GOSSIP_INET.packed, socket.INADDR_ANY)
        self.gossip_recv_socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)

        self.gossip_broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # You can always send a message to the broadcaster directly on gossip_port+1
        if SUPPORTS_REUSEABLE_SOCKET:
            self.gossip_broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.gossip_broadcast_socket.bind((ip, gossip_port+1))
        # Set the multicast-bound packets to have zero ttl, meaning they don't escape
        # the network
        ttl = struct.pack('b', 1)
        self.gossip_broadcast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

        self.http_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if SUPPORTS_REUSEABLE_SOCKET:
            self.http_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.http_socket.bind((ip, http_port))
        self.http_socket.listen(max_http_backlog)

        return self


class GossipListener(asyncio.DatagramProtocol):
    def __init__(self, server):
        self.server = server

    def connection_made(self, transport):
        logger.debug('Listener ready')
        self.transport = transport

    def datagram_received(self, addr, data):
        self.server.on_remote_request(addr, data)


class GossipBroadcaster(asyncio.DatagramProtocol):
    def __init__(self, server):
        self.server = server
        self._datagram_received = None

    def connection_made(self, transport):
        logger.debug('Broadcast ready')
        self.transport = transport

    def datagram_received(self, addr, data):
        self.server.on_remote_response(addr, data)
