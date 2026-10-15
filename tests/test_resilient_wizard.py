import io
import unittest
from unittest.mock import patch
from aegis.cli import _choose, menu, wizard

class ResilientWizardTests(unittest.TestCase):
    def test_invalid_choice_retries(self):
        with patch('builtins.input', side_effect=['bad', '2']), patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(_choose('choice: ', 3), 1)
        self.assertIn('Try again', out.getvalue())

    def test_invalid_choices_cancel_after_bounded_attempts(self):
        with patch('builtins.input', side_effect=['x', '-1', '8']), patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertIsNone(_choose('choice: ', 3))
        self.assertIn('retry limit reached', out.getvalue().lower())

    def test_eof_cancels_choice_without_traceback(self):
        with patch('builtins.input', side_effect=EOFError), patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertIsNone(_choose('choice: ', 3))
        self.assertIn('Cancelling this step safely', out.getvalue())

    def test_ctrl_c_cancels_choice_without_traceback(self):
        with patch('builtins.input', side_effect=KeyboardInterrupt), patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertIsNone(_choose('choice: ', 3))
        self.assertIn('Cancelling this step safely', out.getvalue())

    def test_menu_eof_exits_cleanly(self):
        with patch('builtins.input', side_effect=EOFError), patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(menu('fixture.json'), 0)
        self.assertIn('Exiting without changes', out.getvalue())

    def test_empty_list_does_not_prompt(self):
        with patch('builtins.input', side_effect=AssertionError('must not prompt')):
            self.assertIsNone(_choose('choice: ', 0))

    def test_missing_inventory_returns_recoverable_error(self):
        with patch('sys.stderr', new_callable=io.StringIO) as err, patch('sys.stdout', new_callable=io.StringIO) as out:
            result = wizard('/path/that/does/not/exist/aegis-fixture.json')
        self.assertEqual(result, 2)
        self.assertIn('Recovery:', out.getvalue())
        self.assertIn('unavailable', err.getvalue().lower())

if __name__ == '__main__':
    unittest.main()
