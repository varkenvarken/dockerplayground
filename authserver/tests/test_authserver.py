import pytest

from authserver import server

@pytest.fixture
def password():
    return '12345678'


def test_checkpassword(password):
    pwhash = server.newpassword(password)
    assert pwhash
    assert server.checkpassword(password, pwhash)
