from authserver import server


class TestClass:

    def test_a(self):
        self.password = server.newpassword('12345678')
