from integration.testcase import CommandTestCase


class ResolveCommand(CommandTestCase):

    async def test_resolve(self):
        await self.make_channel('@abc', '0.01')

        # resolving a channel @abc
        response = await self.resolve('lbry://@abc')
        self.assertSetEqual({'lbry://@abc'}, set(response))
        self.assertIn('certificate', response['lbry://@abc'])
        self.assertNotIn('claim', response['lbry://@abc'])
        self.assertEqual(response['lbry://@abc']['certificate']['name'], '@abc')
        self.assertEqual(response['lbry://@abc']['claims_in_channel'], 0)

        await self.make_claim('foo', '0.01', channel_name='@abc')
        await self.make_claim('foo2', '0.01', channel_name='@abc')

        # resolving a channel @abc with some claims in it
        response = await self.resolve('lbry://@abc')
        self.assertSetEqual({'lbry://@abc'}, set(response))
        self.assertIn('certificate', response['lbry://@abc'])
        self.assertNotIn('claim', response['lbry://@abc'])
        self.assertEqual(response['lbry://@abc']['certificate']['name'], '@abc')
        self.assertEqual(response['lbry://@abc']['claims_in_channel'], 2)

        # resolving claim foo within channel @abc
        response = await self.resolve('lbry://@abc/foo')
        self.assertSetEqual({'lbry://@abc/foo'}, set(response))
        claim = response['lbry://@abc/foo']
        self.assertIn('certificate', claim)
        self.assertIn('claim', claim)
        self.assertEqual(claim['claim']['name'], 'foo')
        self.assertEqual(claim['claim']['channel_name'], '@abc')
        self.assertEqual(claim['certificate']['name'], '@abc')
        self.assertEqual(claim['claims_in_channel'], 0)

        # resolving claim foo by itself
        response = await self.resolve('lbry://foo')
        self.assertSetEqual({'lbry://foo'}, set(response))
        claim = response['lbry://foo']
        self.assertIn('certificate', claim)
        self.assertIn('claim', claim)
        self.assertEqual(claim['claim']['name'], 'foo')
        self.assertEqual(claim['claim']['channel_name'], '@abc')
        self.assertEqual(claim['certificate']['name'], '@abc')
        self.assertEqual(claim['claims_in_channel'], 0)

        # resolving multiple at once
        response = await self.resolve(['lbry://foo', 'lbry://foo2'])
        self.assertSetEqual({'lbry://foo', 'lbry://foo2'}, set(response))
        claim = response['lbry://foo2']
        self.assertIn('certificate', claim)
        self.assertIn('claim', claim)
        self.assertEqual(claim['claim']['name'], 'foo2')
        self.assertEqual(claim['claim']['channel_name'], '@abc')
        self.assertEqual(claim['certificate']['name'], '@abc')
        self.assertEqual(claim['claims_in_channel'], 0)

    async def test_canonical_resolve_url(self):
        kauffj1, kauffj2, grin, gorn1, gorn2, gorn3 = await self.get_account_ids()

        # get canonical url for @kauffj
        channel_k1 = await self.make_channel('@kauffj', '0.01', account_id=kauffj1)
        claim_id1 = channel_k1['claim_id']
        # canonical_url_k1 = (await self.resolve('lbry://@kauffj'))['lbry://@kauffj']['certificate']['canonical_url']

        # check if resolution is proper
        resolve1 = await self.resolve("lbry://@kauffj#{}".format(claim_id1[0]))
        resolve2 = await self.resolve("lbry://@kauffj")
        x = resolve1["lbry://@kauffj#{}".format(claim_id1[0])]
        y = resolve2["lbry://@kauffj"]
        self.assertResolveDictEqual(x, y)

        claim_g1 = await self.make_claim('gornado', '0.02', account_id=gorn1)
        claim_id2 = claim_g1['claim_id']
        await self.make_claim('gornado', '0.01', channel_name='@kauffj', account_id=kauffj1)
        y = await self.resolve("lbry://gornado")
        z = await self.resolve("lbry://@kauffj/gornado")
        qq = z["lbry://@kauffj/gornado"]

    def assertResolveDictEqual(self, resolve_dict1, resolve_dict2):
        if resolve_dict1['certificate'].get('valid_at_height'):
            resolve_dict1['certificate'].pop('valid_at_height')

        if resolve_dict2['certificate'].get('valid_at_height'):
            resolve_dict2['certificate'].pop('valid_at_height')

        self.assertDictEqual(resolve_dict1, resolve_dict2)

    async def get_account_ids(self):
        account_ids = list()
        for i in range(1, 7):
            account_id = (await self.daemon.jsonrpc_account_create('account_{}'.format(i)))['id']
            account_address = await self.daemon.jsonrpc_address_unused(account_id)
            result = await self.out(self.daemon.jsonrpc_wallet_send('1.0', account_address))
            await self.confirm_tx(result['txid'])
            account_ids.append(account_id)

        await self.generate(5)

        return account_ids
