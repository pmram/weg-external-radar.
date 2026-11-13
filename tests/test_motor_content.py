import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from motor_content import classify_html, inspect

class MotorContentTests(unittest.TestCase):
    def test_english_electric_motor(self):
        s,t,_=classify_html(b"<html><body>WEG electric motors for industrial applications</body></html>")
        self.assertEqual(s,"Referências a motores")
        self.assertIn("electric motors",t)
    def test_portuguese(self):
        s,t,_=classify_html("<html><body>Motores elétricos industriais</body></html>".encode())
        self.assertEqual(s,"Referências a motores")
    def test_russian(self):
        s,t,_=classify_html("<body>Электродвигатели для промышленности</body>".encode())
        self.assertEqual(s,"Referências a motores")
    def test_kazakh(self):
        s,t,_=classify_html("<body>электр қозғалтқыштары</body>".encode())
        self.assertEqual(s,"Referências a motores")
    def test_german_weg_is_not_evidence(self):
        s,t,_=classify_html(b"<body>Auf dem Weg nach Hause</body>")
        self.assertEqual(s,"Sem referências")
    def test_script_tags_do_not_count(self):
        s,t,_=classify_html(b"<html><script>electric motors</script><p>About company</p></html>")
        self.assertEqual(s,"Sem referências")
    def test_generic_motor_is_weak(self):
        s,t,_=classify_html(b"<body>Our motor portfolio</body>")
        self.assertEqual(s,"Indício fraco")
    def test_large_response_not_accepted(self):
        response=MagicMock()
        response.status=200
        response.getheader.side_effect=lambda n,default="": "text/html" if n=="Content-Type" else "500000" if n=="Content-Length" else default
        conn=MagicMock()
        conn.getresponse.return_value=response
        with patch("motor_content.public_addresses",return_value=["8.8.8.8"]),patch("motor_content.PinnedHTTPS",return_value=conn):
            r=inspect("weg-example.test","https://weg-example.test/")
        self.assertEqual(r["motor_status"],"Não verificado")
        response.read.assert_not_called()
    def test_no_external_link_follow(self):
        response=MagicMock()
        response.status=301
        conn=MagicMock()
        conn.getresponse.return_value=response
        with patch("motor_content.public_addresses",return_value=["8.8.8.8"]),patch("motor_content.PinnedHTTPS",return_value=conn):
            r=inspect("weg-example.test","https://weg-example.test/")
        self.assertEqual(r["motor_status"],"Não verificado")
        conn.request.assert_called_once()
if __name__=="__main__":
    unittest.main()
