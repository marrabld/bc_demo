#!/usr/bin/env python3

from tools import COINBASE, Ledger, Miner, Validator, Block, Wallet, TARGET, MEMPOOL, FullNode, CANDIDATE_BLOCKS, \
    BLOCK_LIMIT
import pickle
import time
import asyncio

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

f = FullNode()
l = Ledger()

print('Running')


async def echo_server(reader, writer):
    while True:
        data = await reader.read(10000)  # Max number of bytes to read
        if not data:
            break

        print('=====================================')
        print('Transaction found')
        print('=====================================')
        print(data)
        data = pickle.loads(data)
        print(' ')
        for k in data.keys():
            print(k + ' : ' + str(data[k]))
        print(' ')
        print('=====================================')
        print('Validating Transaction')
        print('=====================================')
        print('Valid Transaction Found ? {}'.format(f.v.validate_transaction(data)))
        print('=====================================')
        MEMPOOL.append(data)

        time.sleep(2)
        if len(MEMPOOL) >= BLOCK_LIMIT:
            print('=====================================')
            print('Mining Candidate Block')
            f.gen_candidate_block()
            f.l.add_block(CANDIDATE_BLOCKS[0])
            CANDIDATE_BLOCKS.pop()
            print('=====================================')

        print(' Done ')
        for ii, item in enumerate(f.l.block_chain):
            print('Block {} hash :: {}'.format(ii, item))
        print('=====================================')

        print(f.l)

        writer.write(b'Received Transaction')

        await writer.drain()  # Flow control, see later
    writer.close()


async def main(host, port):
    server = await asyncio.start_server(echo_server, host, port)
    await server.serve_forever()


asyncio.run(main(HOST, PORT))
