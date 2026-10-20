import unittest
from contextlib import ExitStack, nullcontext
from unittest.mock import patch
import main

class CliTransportTests(unittest.TestCase):
    def test_confirmed_change_uses_shared_engine_synchronously(self):
        pool = {'transport':'pck','nodes':[{}]}
        with ExitStack() as stack:
            stack.enter_context(patch.object(main,'get_pools',return_value={'pool':pool}))
            stack.enter_context(patch.object(main,'console'))
            stack.enter_context(patch.object(main.Prompt,'ask',side_effect=['2','']))
            stack.enter_context(patch.object(main.Confirm,'ask',return_value=True))
            stack.enter_context(patch.object(main,'mutation_lock',side_effect=nullcontext))
            start=stack.enter_context(patch.object(main,'start_change',return_value=(True,'queued')))
            run=stack.enter_context(patch.object(main,'run_change'))
            main.change_pool_transport_flow('pool')
            start.assert_called_once_with('pool','stealth',background=False)
            run.assert_called_once_with('pool')

    def test_cancel_does_not_queue_change(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(main,'get_pools',return_value={'pool':{'transport':'pck','nodes':[{}]}}))
            stack.enter_context(patch.object(main,'console'))
            stack.enter_context(patch.object(main.Prompt,'ask',return_value='2'))
            stack.enter_context(patch.object(main.Confirm,'ask',return_value=False))
            start=stack.enter_context(patch.object(main,'start_change'))
            main.change_pool_transport_flow('pool')
            start.assert_not_called()

    def test_other_cli_pool_operations_block_while_change_is_active(self):
        with patch.object(main,'mutation_lock',side_effect=nullcontext), patch.object(main,'transport_busy',return_value=True), patch.object(main,'console'):
            action=main.pool_mutation_flow(lambda: self.fail('Mutation must be blocked'))
            action()
