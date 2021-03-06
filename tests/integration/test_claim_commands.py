import hashlib
import tempfile
from binascii import unhexlify

import ecdsa

from lbrynet.wallet.transaction import Transaction, Output
from torba.client.errors import InsufficientFundsError
from lbrynet.schema.compat import OldClaimMessage

from integration.testcase import CommandTestCase
from torba.client.hash import sha256, Base58


class ChannelCommands(CommandTestCase):

    async def test_create_channel_names(self):
        # claim new name
        await self.channel_create('@foo')
        self.assertEqual(len(await self.daemon.jsonrpc_channel_list()), 1)
        await self.assertBalance(self.account, '8.991893')

        # fail to claim duplicate
        with self.assertRaisesRegex(Exception, "You already have a channel under the name '@foo'."):
            await self.channel_create('@foo')

        # fail to claim invalid name
        with self.assertRaisesRegex(Exception, "Channel names must start with '@' symbol."):
            await self.channel_create('foo')

        # nothing's changed after failed attempts
        self.assertEqual(len(await self.daemon.jsonrpc_channel_list()), 1)
        await self.assertBalance(self.account, '8.991893')

        # succeed overriding duplicate restriction
        await self.channel_create('@foo', allow_duplicate_name=True)
        self.assertEqual(len(await self.daemon.jsonrpc_channel_list()), 2)
        await self.assertBalance(self.account, '7.983786')

    async def test_channel_bids(self):
        # enough funds
        tx = await self.channel_create('@foo', '5.0')
        claim_id = tx['outputs'][0]['claim_id']
        self.assertEqual(len(await self.daemon.jsonrpc_channel_list()), 1)
        await self.assertBalance(self.account, '4.991893')

        # bid preserved on update
        tx = await self.channel_update(claim_id)
        self.assertEqual(tx['outputs'][0]['amount'], '5.0')

        # bid changed on update
        tx = await self.channel_update(claim_id, bid='4.0')
        self.assertEqual(tx['outputs'][0]['amount'], '4.0')

        await self.assertBalance(self.account, '5.991447')

        # not enough funds
        with self.assertRaisesRegex(
                InsufficientFundsError, "Not enough funds to cover this transaction."):
            await self.channel_create('@foo2', '9.0')
        self.assertEqual(len(await self.daemon.jsonrpc_channel_list()), 1)
        await self.assertBalance(self.account, '5.991447')

        # spend exactly amount available, no change
        tx = await self.channel_create('@foo3', '5.981266')
        await self.assertBalance(self.account, '0.0')
        self.assertEqual(len(tx['outputs']), 1)  # no change
        self.assertEqual(len(await self.daemon.jsonrpc_channel_list()), 2)

    async def test_setting_channel_fields(self):
        values = {
            'tags': ["cool", "awesome"],
            'title': "Cool Channel",
            'description': "Best channel on LBRY.",
            'thumbnail_url': "https://co.ol/thumbnail.png",
            'languages': ["en-US"],
            'locations': ['US::Manchester'],
            'contact_email': "human@email.com",
            'homepage_url': "https://co.ol",
            'cover_url': "https://co.ol/cover.png",
        }
        fixed_values = values.copy()
        fixed_values['languages'] = ['en-US']
        fixed_values['locations'] = [{'country': 'US', 'city': 'Manchester'}]

        # create new channel with all fields set
        tx = await self.out(self.channel_create('@bigchannel', **values))
        txo = tx['outputs'][0]
        self.assertEqual(
            txo['value']['channel'],
            {'public_key': txo['value']['channel']['public_key'], **fixed_values}
        )

        # create channel with nothing set
        tx = await self.out(self.channel_create('@lightchannel'))
        txo = tx['outputs'][0]
        self.assertEqual(
            txo['value']['channel'],
            {'public_key': txo['value']['channel']['public_key']}
        )

        # create channel with just some tags
        tx = await self.out(self.channel_create('@updatedchannel', tags='blah'))
        txo = tx['outputs'][0]
        claim_id = txo['claim_id']
        public_key = txo['value']['channel']['public_key']
        self.assertEqual(
            txo['value']['channel'],
            {'public_key': public_key, 'tags': ['blah']}
        )

        # update channel setting all fields
        tx = await self.out(self.channel_update(claim_id, **values))
        txo = tx['outputs'][0]
        fixed_values['public_key'] = public_key
        fixed_values['tags'].insert(0, 'blah')  # existing tag
        self.assertEqual(
            txo['value']['channel'],
            fixed_values
        )

        # clearing and settings tags
        tx = await self.out(self.channel_update(claim_id, tags='single', clear_tags=True))
        txo = tx['outputs'][0]
        fixed_values['tags'] = ['single']
        self.assertEqual(
            txo['value']['channel'],
            fixed_values
        )

        # reset signing key
        tx = await self.out(self.channel_update(claim_id, new_signing_key=True))
        txo = tx['outputs'][0]
        self.assertNotEqual(
            txo['value']['channel']['public_key'],
            fixed_values['public_key']
        )

        # send channel to someone else
        new_account = await self.daemon.jsonrpc_account_create('second account')
        account2_id, account2 = new_account['id'], self.daemon.get_account_or_error(new_account['id'])

        # before sending
        self.assertEqual(len(await self.daemon.jsonrpc_channel_list()), 3)
        self.assertEqual(len(await self.daemon.jsonrpc_channel_list(account_id=account2_id)), 0)

        other_address = await account2.receiving.get_or_create_usable_address()
        tx = await self.out(self.channel_update(claim_id, claim_address=other_address))

        # after sending
        self.assertEqual(len(await self.daemon.jsonrpc_channel_list()), 2)
        self.assertEqual(len(await self.daemon.jsonrpc_channel_list(account_id=account2_id)), 1)

        # shoud not have private key
        txo = (await account2.get_channels())[0]
        self.assertIsNone(txo.private_key)

        # send the private key too
        txoid = f"{tx['outputs'][0]['txid']}:{tx['outputs'][0]['nout']}"
        account2.channel_keys[txoid] = self.account.channel_keys[txoid]

        # now should have private key
        txo = (await account2.get_channels())[0]
        self.assertIsNotNone(txo.private_key)


class StreamCommands(CommandTestCase):

    async def test_create_stream_names(self):
        # claim new name
        await self.stream_create('foo')
        self.assertEqual(len(await self.daemon.jsonrpc_claim_list()), 1)
        await self.assertBalance(self.account, '8.993893')

        # fail to claim duplicate
        with self.assertRaisesRegex(
                Exception, "You already have a stream claim published under the name 'foo'."):
            await self.stream_create('foo')

        # fail claim starting with @
        with self.assertRaisesRegex(
                Exception, "Stream names cannot start with '@' symbol."):
            await self.stream_create('@foo')

        self.assertEqual(len(await self.daemon.jsonrpc_claim_list()), 1)
        await self.assertBalance(self.account, '8.993893')

        # succeed overriding duplicate restriction
        await self.stream_create('foo', allow_duplicate_name=True)
        self.assertEqual(len(await self.daemon.jsonrpc_claim_list()), 2)
        await self.assertBalance(self.account, '7.987786')

    async def test_stream_bids(self):
        # enough funds
        tx = await self.stream_create('foo', '2.0')
        claim_id = tx['outputs'][0]['claim_id']
        self.assertEqual(len(await self.daemon.jsonrpc_claim_list()), 1)
        await self.assertBalance(self.account, '7.993893')

        # bid preserved on update
        tx = await self.stream_update(claim_id)
        self.assertEqual(tx['outputs'][0]['amount'], '2.0')

        # bid changed on update
        tx = await self.stream_update(claim_id, bid='3.0')
        self.assertEqual(tx['outputs'][0]['amount'], '3.0')

        await self.assertBalance(self.account, '6.993384')

        # not enough funds
        with self.assertRaisesRegex(
                InsufficientFundsError, "Not enough funds to cover this transaction."):
            await self.stream_create('foo2', '9.0')
        self.assertEqual(len(await self.daemon.jsonrpc_claim_list()), 1)
        await self.assertBalance(self.account, '6.993384')

        # spend exactly amount available, no change
        tx = await self.stream_create('foo3', '6.98527700')
        await self.assertBalance(self.account, '0.0')
        self.assertEqual(len(tx['outputs']), 1)  # no change
        self.assertEqual(len(await self.daemon.jsonrpc_claim_list()), 2)

    async def test_publishing_checks_all_accounts_for_channel(self):
        account1_id, account1 = self.account.id, self.account
        new_account = await self.daemon.jsonrpc_account_create('second account')
        account2_id, account2 = new_account['id'], self.daemon.get_account_or_error(new_account['id'])

        await self.out(self.channel_create('@spam', '1.0'))
        self.assertEqual('8.989893', await self.daemon.jsonrpc_account_balance())

        result = await self.out(self.daemon.jsonrpc_account_send(
            '5.0', await self.daemon.jsonrpc_address_unused(account2_id)
        ))
        await self.confirm_tx(result['txid'])

        self.assertEqual('3.989769', await self.daemon.jsonrpc_account_balance())
        self.assertEqual('5.0', await self.daemon.jsonrpc_account_balance(account2_id))

        baz_tx = await self.out(self.channel_create('@baz', '1.0', account_id=account2_id))
        baz_id = baz_tx['outputs'][0]['claim_id']

        channels = await self.out(self.daemon.jsonrpc_channel_list(account1_id))
        self.assertEqual(len(channels), 1)
        self.assertEqual(channels[0]['name'], '@spam')
        self.assertEqual(channels, await self.out(self.daemon.jsonrpc_channel_list()))

        channels = await self.out(self.daemon.jsonrpc_channel_list(account2_id))
        self.assertEqual(len(channels), 1)
        self.assertEqual(channels[0]['name'], '@baz')

        # defaults to using all accounts to lookup channel
        await self.stream_create('hovercraft1', channel_id=baz_id)
        self.assertEqual((await self.claim_search('hovercraft1'))[0]['channel_name'], '@baz')
        # uses only the specific accounts which contains the channel
        await self.stream_create('hovercraft2', channel_id=baz_id, channel_account_id=[account2_id])
        self.assertEqual((await self.claim_search('hovercraft2'))[0]['channel_name'], '@baz')
        # fails when specifying account which does not contain channel
        with self.assertRaisesRegex(ValueError, "Couldn't find channel with channel_id"):
            await self.stream_create(
                'hovercraft3', channel_id=baz_id, channel_account_id=[account1_id]
            )

    async def test_setting_stream_fields(self):
        values = {
            'tags': ["cool", "awesome"],
            'title': "Cool Content",
            'description': "Best content on LBRY.",
            'thumbnail_url': "https://co.ol/thumbnail.png",
            'languages': ["en"],
            'locations': ['{"country": "UA"}'],

            'author': "Jules Verne",
            'license': 'Public Domain',
            'license_url': "https://co.ol/license",
            'release_time': 123456,

            'fee_currency': 'usd',
            'fee_amount': '2.99',
            'fee_address': 'mmCsWAiXMUVecFQ3fVzUwvpT9XFMXno2Ca',

            'video_width': 800,
            'video_height': 600
        }
        fixed_values = values.copy()
        fixed_values['languages'] = ['en']
        fixed_values['locations'] = [{'country': 'UA'}]

        # create new channel with all fields set
        tx = await self.out(self.stream_create('big', **values))
        txo = tx['outputs'][0]
        stream = txo['value']['stream']
        fixed_values['sd_hash'] = stream['sd_hash']
        fixed_values['file'] = stream['file']
        fixed_values['media_type'] = 'application/octet-stream'
        fixed_values['release_time'] = str(values['release_time'])
        fixed_values['fee'] = {
            'address': fixed_values.pop('fee_address'),
            'amount': float(fixed_values.pop('fee_amount')),
            'currency': fixed_values.pop('fee_currency').upper()
        }
        fixed_values['video'] = {
            'height': fixed_values.pop('video_height'),
            'width': fixed_values.pop('video_width')
        }
        self.assertEqual(stream, fixed_values)

        # create channel with nothing set
        tx = await self.out(self.stream_create('light'))
        txo = tx['outputs'][0]
        self.assertEqual(
            txo['value']['stream'], {
                'file': {'size': '3'},
                'media_type': 'application/octet-stream',
                'sd_hash': txo['value']['stream']['sd_hash']
            }
        )

        # create channel with just some tags
        tx = await self.out(self.stream_create('updated', tags='blah'))
        txo = tx['outputs'][0]
        claim_id = txo['claim_id']
        fixed_values['sd_hash'] = txo['value']['stream']['sd_hash']
        self.assertEqual(
            txo['value']['stream'], {
                'file': {'size': '3'},
                'media_type': 'application/octet-stream',
                'sd_hash': fixed_values['sd_hash'],
                'tags': ['blah']
            }
        )

        # update channel setting all fields
        tx = await self.out(self.stream_update(claim_id, **values))
        txo = tx['outputs'][0]
        fixed_values['tags'].insert(0, 'blah')  # existing tag
        self.assertEqual(txo['value']['stream'], fixed_values)

        # clearing and settings tags
        tx = await self.out(self.stream_update(claim_id, tags='single', clear_tags=True))
        txo = tx['outputs'][0]
        fixed_values['tags'] = ['single']
        self.assertEqual(txo['value']['stream'], fixed_values)

        # send claim to someone else
        new_account = await self.daemon.jsonrpc_account_create('second account')
        account2_id, account2 = new_account['id'], self.daemon.get_account_or_error(new_account['id'])

        # before sending
        self.assertEqual(len(await self.daemon.jsonrpc_claim_list()), 3)
        self.assertEqual(len(await self.daemon.jsonrpc_claim_list(account_id=account2_id)), 0)

        other_address = await account2.receiving.get_or_create_usable_address()
        tx = await self.out(self.stream_update(claim_id, claim_address=other_address))

        # after sending
        self.assertEqual(len(await self.daemon.jsonrpc_claim_list()), 2)
        self.assertEqual(len(await self.daemon.jsonrpc_claim_list(account_id=account2_id)), 1)

    async def test_create_update_and_abandon_claim(self):
        await self.assertBalance(self.account, '10.0')

        tx = await self.stream_create(bid='2.5')  # creates new claim
        claim_id = tx['outputs'][0]['claim_id']
        txs = await self.out(self.daemon.jsonrpc_transaction_list())
        self.assertEqual(len(txs[0]['claim_info']), 1)
        self.assertEqual(txs[0]['confirmations'], 1)
        self.assertEqual(txs[0]['claim_info'][0]['balance_delta'], '-2.5')
        self.assertEqual(txs[0]['claim_info'][0]['claim_id'], claim_id)
        self.assertEqual(txs[0]['value'], '0.0')
        self.assertEqual(txs[0]['fee'], '-0.020107')
        await self.assertBalance(self.account, '7.479893')

        await self.stream_update(claim_id, bid='1.0')  # updates previous claim
        txs = await self.out(self.daemon.jsonrpc_transaction_list())
        self.assertEqual(len(txs[0]['update_info']), 1)
        self.assertEqual(txs[0]['update_info'][0]['balance_delta'], '1.5')
        self.assertEqual(txs[0]['update_info'][0]['claim_id'], claim_id)
        self.assertEqual(txs[0]['value'], '0.0')
        self.assertEqual(txs[0]['fee'], '-0.000184')
        await self.assertBalance(self.account, '8.979709')

        await self.stream_abandon(claim_id)
        txs = await self.out(self.daemon.jsonrpc_transaction_list())
        self.assertEqual(len(txs[0]['abandon_info']), 1)
        self.assertEqual(txs[0]['abandon_info'][0]['balance_delta'], '1.0')
        self.assertEqual(txs[0]['abandon_info'][0]['claim_id'], claim_id)
        self.assertEqual(txs[0]['value'], '0.0')
        self.assertEqual(txs[0]['fee'], '-0.000107')
        await self.assertBalance(self.account, '9.979602')

    async def test_abandoning_claim_at_loss(self):
        await self.assertBalance(self.account, '10.0')
        tx = await self.stream_create(bid='0.0001')
        await self.assertBalance(self.account, '9.979793')
        await self.stream_abandon(tx['outputs'][0]['claim_id'])
        await self.assertBalance(self.account, '9.97968399')

    async def test_publish(self):

        # errors on missing arguments to create a stream
        with self.assertRaisesRegex(Exception, "'bid' is a required argument for new publishes."):
            await self.daemon.jsonrpc_publish('foo')

        with self.assertRaisesRegex(Exception, "'file_path' is a required argument for new publishes."):
            await self.daemon.jsonrpc_publish('foo', bid='1.0')

        # successfully create stream
        with tempfile.NamedTemporaryFile() as file:
            file.write(b'hi')
            file.flush()
            tx1 = await self.publish('foo', bid='1.0', file_path=file.name)

        # doesn't error on missing arguments when doing an update stream
        tx2 = await self.publish('foo', tags='updated')
        self.assertEqual(
            tx1['outputs'][0]['claim_id'],
            tx2['outputs'][0]['claim_id']
        )

        # update conflict with two claims of the same name
        tx3 = await self.stream_create('foo', allow_duplicate_name=True)
        with self.assertRaisesRegex(Exception, "There are 2 claims for 'foo'"):
            await self.daemon.jsonrpc_publish('foo')

        # abandon duplicate stream
        await self.stream_abandon(tx3['outputs'][0]['claim_id'])

        # publish to a channel
        await self.channel_create('@abc')
        tx3 = await self.publish('foo', channel_name='@abc')
        r = await self.resolve('lbry://@abc/foo')
        self.assertEqual(
            r['lbry://@abc/foo']['claim']['claim_id'],
            tx3['outputs'][0]['claim_id']
        )

        # publishing again re-signs with the same channel
        tx4 = await self.publish('foo', languages='uk-UA')
        r = await self.resolve('lbry://@abc/foo')
        claim = r['lbry://@abc/foo']['claim']
        self.assertEqual(claim['txid'], tx4['outputs'][0]['txid'])
        self.assertEqual(claim['channel_name'], '@abc')
        self.assertEqual(claim['signature_is_valid'], True)
        self.assertEqual(claim['value']['stream']['languages'], ['uk-UA'])

    async def test_claim_search(self):
        # search for channel claim
        channel = await self.channel_create('@abc', '1.0')
        channel_id, txid = channel['outputs'][0]['claim_id'], channel['txid']
        value = channel['outputs'][0]['value']

        claims = await self.claim_search('@abc')
        self.assertEqual(claims[0]['value'], value)

        claims = await self.claim_search(txid=txid, nout=0)
        self.assertEqual(claims[0]['value'], value)

        claims = await self.claim_search(claim_id=channel_id)
        self.assertEqual(claims[0]['value'], value)

        await self.channel_abandon(txid=txid, nout=0)
        self.assertEqual(len(await self.claim_search(txid=txid, nout=0)), 0)

        # search stream claims
        channel = await self.channel_create('@abc', '1.0')
        channel_id, txid = channel['outputs'][0]['claim_id'], channel['txid']

        signed = await self.stream_create('on-channel-claim', '0.0001', channel_id=channel_id)
        unsigned = await self.stream_create('unsigned', '0.0001')

        claims = await self.claim_search('on-channel-claim')
        self.assertEqual(claims[0]['value'], signed['outputs'][0]['value'])

        claims = await self.claim_search('unsigned')
        self.assertEqual(claims[0]['value'], unsigned['outputs'][0]['value'])

        # list streams in a channel
        await self.stream_create('on-channel-claim-2', '0.0001', channel_id=channel_id)
        await self.stream_create('on-channel-claim-3', '0.0001', channel_id=channel_id)

        claims = await self.claim_search(channel_id=channel_id)
        self.assertEqual(len(claims), 3)

        await self.stream_abandon(claim_id=claims[0]['claim_id'])
        await self.stream_abandon(claim_id=claims[1]['claim_id'])
        await self.stream_abandon(claim_id=claims[2]['claim_id'])

        claims = await self.claim_search(channel_id=channel_id)
        self.assertEqual(len(claims), 0)

        tx = await self.daemon.jsonrpc_account_fund(None, None, '0.001', outputs=100, broadcast=True)
        await self.confirm_tx(tx.id)

        # 4 claims per block, 3 blocks. Sorted by height (descending) then claim_id (ascending).
        claims = []
        for j in range(3):
            same_height_claims = []
            for k in range(3):
                claim_tx = await self.stream_create(f'c{j}-{k}', '0.000001', channel_id=channel_id, confirm=False)
                same_height_claims.append(claim_tx['outputs'][0]['claim_id'])
                await self.on_transaction_dict(claim_tx)
            claim_tx = await self.stream_create(f'c{j}-4', '0.000001', channel_id=channel_id, confirm=True)
            same_height_claims.append(claim_tx['outputs'][0]['claim_id'])
            same_height_claims.sort(key=lambda x: int(x, 16))
            claims = same_height_claims + claims

        page = await self.claim_search(page_size=20, channel_id=channel_id)
        page_claim_ids = [item['claim_id'] for item in page]
        self.assertEqual(page_claim_ids, claims)

        page = await self.claim_search(page_size=6, channel_id=channel_id)
        page_claim_ids = [item['claim_id'] for item in page]
        self.assertEqual(page_claim_ids, claims[:6])

        out_of_bounds = await self.claim_search(page=2, page_size=20, channel_id=channel_id)
        self.assertEqual(out_of_bounds, [])

    async def test_abandoned_channel_with_signed_claims(self):
        channel = (await self.channel_create('@abc', '1.0'))['outputs'][0]
        orphan_claim = await self.stream_create('on-channel-claim', '0.0001', channel_id=channel['claim_id'])
        await self.channel_abandon(txid=channel['txid'], nout=0)
        channel = (await self.channel_create('@abc', '1.0'))['outputs'][0]
        orphan_claim_id = orphan_claim['outputs'][0]['claim_id']

        # Original channel doesnt exists anymore, so the signature is invalid. For invalid signatures, resolution is
        # only possible outside a channel
        response = await self.resolve('lbry://@abc/on-channel-claim')
        self.assertNotIn('claim', response['lbry://@abc/on-channel-claim'])
        response = await self.resolve('lbry://on-channel-claim')
        self.assertFalse(response['lbry://on-channel-claim']['claim']['signature_is_valid'])
        direct_uri = 'lbry://on-channel-claim#' + orphan_claim_id
        response = await self.resolve(direct_uri)
        self.assertFalse(response[direct_uri]['claim']['signature_is_valid'])
        await self.stream_abandon(claim_id=orphan_claim_id)

        uri = 'lbry://@abc/on-channel-claim'
        # now, claim something on this channel (it will update the invalid claim, but we save and forcefully restore)
        valid_claim = await self.stream_create('on-channel-claim', '0.00000001', channel_id=channel['claim_id'])
        # resolves normally
        response = await self.resolve(uri)
        self.assertTrue(response[uri]['claim']['signature_is_valid'])

        # ooops! claimed a valid conflict! (this happens on the wild, mostly by accident or race condition)
        await self.stream_create(
            'on-channel-claim', '0.00000001', channel_id=channel['claim_id'], allow_duplicate_name=True
        )

        # it still resolves! but to the older claim
        response = await self.resolve(uri)
        self.assertTrue(response[uri]['claim']['signature_is_valid'])
        self.assertEqual(response[uri]['claim']['txid'], valid_claim['txid'])
        claims = (await self.daemon.jsonrpc_claim_search('on-channel-claim'))['items']
        self.assertEqual(2, len(claims))
        signer_ids = set([claim['value'].signing_channel_id for claim in claims])
        self.assertEqual({channel['claim_id']}, signer_ids)

    async def test_normalization_resolution(self):

        # this test assumes that the lbrycrd forks normalization at height == 250 on regtest

        c1 = await self.stream_create('ΣίσυφοςﬁÆ', '0.1')
        c2 = await self.stream_create('ΣΊΣΥΦΟσFIæ', '0.2')

        r1 = await self.daemon.jsonrpc_resolve(urls='lbry://ΣίσυφοςﬁÆ')
        r2 = await self.daemon.jsonrpc_resolve(urls='lbry://ΣΊΣΥΦΟσFIæ')

        r1c = list(r1.values())[0]['claim']['claim_id']
        r2c = list(r2.values())[0]['claim']['claim_id']
        self.assertEqual(c1['outputs'][0]['claim_id'], r1c)
        self.assertEqual(c2['outputs'][0]['claim_id'], r2c)
        self.assertNotEqual(r1c, r2c)

        await self.generate(50)
        head = await self.daemon.jsonrpc_block_show()
        self.assertTrue(head['height'] > 250)

        r3 = await self.daemon.jsonrpc_resolve(urls='lbry://ΣίσυφοςﬁÆ')
        r4 = await self.daemon.jsonrpc_resolve(urls='lbry://ΣΊΣΥΦΟσFIæ')

        r3c = list(r3.values())[0]['claim']['claim_id']
        r4c = list(r4.values())[0]['claim']['claim_id']
        r3n = list(r3.values())[0]['claim']['name']
        r4n = list(r4.values())[0]['claim']['name']

        self.assertEqual(c2['outputs'][0]['claim_id'], r3c)
        self.assertEqual(c2['outputs'][0]['claim_id'], r4c)
        self.assertEqual(r3c, r4c)
        self.assertEqual(r3n, r4n)

    async def test_resolve_old_claim(self):
        channel = await self.daemon.jsonrpc_channel_create('@olds', '1.0')
        await self.confirm_tx(channel.id)
        address = channel.outputs[0].get_address(self.account.ledger)
        claim = generate_signed_legacy('example', address, channel.outputs[0])
        tx = await Transaction.claim_create('example', claim.SerializeToString(), 1, address, [self.account], self.account)
        await tx.sign([self.account])
        await self.broadcast(tx)
        await self.confirm_tx(tx.id)

        response = await self.daemon.jsonrpc_resolve(urls='@olds/example')
        self.assertTrue(response['@olds/example']['claim']['signature_is_valid'])

        claim.publisherSignature.signature = bytes(reversed(claim.publisherSignature.signature))
        tx = await Transaction.claim_create(
            'bad_example', claim.SerializeToString(), 1, address, [self.account], self.account
        )
        await tx.sign([self.account])
        await self.broadcast(tx)
        await self.confirm_tx(tx.id)

        response = await self.daemon.jsonrpc_resolve(urls='bad_example')
        self.assertFalse(response['bad_example']['claim']['signature_is_valid'], response)
        response = await self.daemon.jsonrpc_resolve(urls='@olds/bad_example')
        self.assertEqual('URI lbry://@olds/bad_example cannot be resolved', response['@olds/bad_example']['error'])


def generate_signed_legacy(name: str, address: bytes, output: Output):
    decoded_address = Base58.decode(address)
    claim = OldClaimMessage()
    claim.ParseFromString(unhexlify(
        '080110011aee04080112a604080410011a2b4865726520617265203520526561736f6e73204920e29da4e'
        'fb88f204e657874636c6f7564207c20544c4722920346696e64206f7574206d6f72652061626f7574204e'
        '657874636c6f75643a2068747470733a2f2f6e657874636c6f75642e636f6d2f0a0a596f752063616e206'
        '6696e64206d65206f6e20746865736520736f6369616c733a0a202a20466f72756d733a2068747470733a'
        '2f2f666f72756d2e6865617679656c656d656e742e696f2f0a202a20506f64636173743a2068747470733'
        'a2f2f6f6666746f706963616c2e6e65740a202a2050617472656f6e3a2068747470733a2f2f7061747265'
        '6f6e2e636f6d2f7468656c696e757867616d65720a202a204d657263683a2068747470733a2f2f7465657'
        '37072696e672e636f6d2f73746f7265732f6f6666696369616c2d6c696e75782d67616d65720a202a2054'
        '77697463683a2068747470733a2f2f7477697463682e74762f786f6e64616b0a202a20547769747465723'
        'a2068747470733a2f2f747769747465722e636f6d2f7468656c696e757867616d65720a0a2e2e2e0a6874'
        '7470733a2f2f7777772e796f75747562652e636f6d2f77617463683f763d4672546442434f535f66632a0'
        'f546865204c696e75782047616d6572321c436f7079726967687465642028636f6e746163742061757468'
        '6f722938004a2968747470733a2f2f6265726b2e6e696e6a612f7468756d626e61696c732f46725464424'
        '34f535f666352005a001a41080110011a30040e8ac6e89c061f982528c23ad33829fd7146435bf7a4cc22'
        'f0bff70c4fe0b91fd36da9a375e3e1c171db825bf5d1f32209766964656f2f6d70342a5c080110031a406'
        '2b2dd4c45e364030fbfad1a6fefff695ebf20ea33a5381b947753e2a0ca359989a5cc7d15e5392a0d354c'
        '0b68498382b2701b22c03beb8dcb91089031b871e72214feb61536c007cdf4faeeaab4876cb397feaf6b51'
    ))
    claim.ClearField("publisherSignature")
    digest = sha256(b''.join([
        decoded_address,
        claim.SerializeToString(),
        output.claim_hash
    ]))
    private_key = ecdsa.SigningKey.from_pem(output.private_key, hashfunc=hashlib.sha256)
    signature = private_key.sign_digest_deterministic(digest, hashfunc=hashlib.sha256)
    claim.publisherSignature.version = 1
    claim.publisherSignature.signatureType = 1
    claim.publisherSignature.signature = signature
    claim.publisherSignature.certificateId = output.claim_hash
    return claim


class SupportCommands(CommandTestCase):

    async def test_regular_supports_and_tip_supports(self):
        # account2 will be used to send tips and supports to account1
        account2_id = (await self.daemon.jsonrpc_account_create('second account'))['id']
        account2 = self.daemon.get_account_or_error(account2_id)

        # send account2 5 LBC out of the 10 LBC in account1
        result = await self.out(self.daemon.jsonrpc_account_send(
            '5.0', await self.daemon.jsonrpc_address_unused(account2_id)
        ))
        await self.on_transaction_dict(result)

        # account1 and account2 balances:
        await self.assertBalance(self.account, '4.999876')
        await self.assertBalance(account2,     '5.0')

        # create the claim we'll be tipping and supporting
        tx = await self.stream_create()
        claim_id = tx['outputs'][0]['claim_id']

        # account1 and account2 balances:
        await self.assertBalance(self.account, '3.979769')
        await self.assertBalance(account2,     '5.0')

        # send a tip to the claim using account2
        tip = await self.out(
            self.daemon.jsonrpc_support_create(claim_id, '1.0', True, account2_id)
        )
        await self.on_transaction_dict(tip)
        await self.generate(1)
        await self.on_transaction_dict(tip)

        # tips don't affect balance so account1 balance is same but account2 balance went down
        await self.assertBalance(self.account, '3.979769')
        await self.assertBalance(account2,     '3.9998585')

        # verify that the incoming tip is marked correctly as is_tip=True in account1
        txs = await self.out(self.daemon.jsonrpc_transaction_list())
        self.assertEqual(len(txs[0]['support_info']), 1)
        self.assertEqual(txs[0]['support_info'][0]['balance_delta'], '1.0')
        self.assertEqual(txs[0]['support_info'][0]['claim_id'], claim_id)
        self.assertEqual(txs[0]['support_info'][0]['is_tip'], True)
        self.assertEqual(txs[0]['value'], '1.0')
        self.assertEqual(txs[0]['fee'], '0.0')

        # verify that the outgoing tip is marked correctly as is_tip=True in account2
        txs2 = await self.out(
            self.daemon.jsonrpc_transaction_list(account2_id)
        )
        self.assertEqual(len(txs2[0]['support_info']), 1)
        self.assertEqual(txs2[0]['support_info'][0]['balance_delta'], '-1.0')
        self.assertEqual(txs2[0]['support_info'][0]['claim_id'], claim_id)
        self.assertEqual(txs2[0]['support_info'][0]['is_tip'], True)
        self.assertEqual(txs2[0]['value'], '-1.0')
        self.assertEqual(txs2[0]['fee'], '-0.0001415')

        # send a support to the claim using account2
        support = await self.out(
            self.daemon.jsonrpc_support_create(claim_id, '2.0', False, account2_id)
        )
        await self.on_transaction_dict(support)
        await self.generate(1)
        await self.on_transaction_dict(support)

        # account2 balance went down ~2
        await self.assertBalance(self.account, '3.979769')
        await self.assertBalance(account2,     '1.999717')

        # verify that the outgoing support is marked correctly as is_tip=False in account2
        txs2 = await self.out(self.daemon.jsonrpc_transaction_list(account2_id))
        self.assertEqual(len(txs2[0]['support_info']), 1)
        self.assertEqual(txs2[0]['support_info'][0]['balance_delta'], '-2.0')
        self.assertEqual(txs2[0]['support_info'][0]['claim_id'], claim_id)
        self.assertEqual(txs2[0]['support_info'][0]['is_tip'], False)
        self.assertEqual(txs2[0]['value'], '0.0')
        self.assertEqual(txs2[0]['fee'], '-0.0001415')


