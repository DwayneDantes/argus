import unittest

class TestImportChain(unittest.TestCase):
    def test_can_import_ntw(self):
        """
        This test will fail if there is ANY import error in the chain
        that ntw.py depends on. It forces unittest to show the traceback.
        """
        try:
            from app.analysis.ntw import get_final_threat_score
            imported_successfully = True
        except Exception as e:
            imported_successfully = False
            # We will print the exception to see the root cause
            print(f"\n--- IMPORT FAILED ---\n{e}\n---------------------\n")

        self.assertTrue(imported_successfully, "Failed to import the main orchestrator 'ntw.py'. Check console for the underlying error.")