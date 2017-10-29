import os
import logging
import asyncio

from . import GossipServer

try:
    import uvloop
except ImportError:
    uvloop = None

async def create_server(http_port, gossip_port, *, loop, path=None):
    if path is None:
        path = os.path.abspath(os.getcwd())
    gossip_server = GossipServer(path, loop)
    await gossip_server.bind('', http_port, gossip_port)
    return gossip_server


def main(http_port, gossip_port, *, loop=None):
    if loop is None:
        if uvloop:
            loop = uvloop.new_event_loop()
        else:
            loop = asyncio.new_event_loop()
    gossip_server = loop.run_until_complete(
        create_server(http_port, gossip_port, loop=loop))
    print("Server is running...")
    asyncio.ensure_future(gossip_server.start(), loop=loop)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    print("Closing server...")
    gossip_server.close()
    loop.close()


if __name__ == '__main__':
    import argparse

    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        'http_port', default=8080, help='Bind this port as the HTTP server', nargs='?', type=int)
    parser.add_argument('gossip_port', default=8081, help='UDP port to multicast on', nargs='?', type=int)

    args = parser.parse_args()
    main(args.http_port, args.gossip_port)
