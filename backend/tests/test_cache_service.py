from app.services.cache_service import CacheService


class _FakeRedis:
    def __init__(self):
        self.data = {}
        self.closed = False

    def ping(self):
        return True

    def get(self, key):
        return self.data.get(key)

    def setex(self, key, _ttl, payload):
        self.data[key] = payload
        return True

    def delete(self, *keys):
        for key in keys:
            self.data.pop(key, None)
        return len(keys)

    def scan_iter(self, match):
        prefix = match[:-1] if match.endswith("*") else match
        for key in list(self.data.keys()):
            if key.startswith(prefix):
                yield key

    def close(self):
        self.closed = True


def test_cache_service_set_get_delete_prefix():
    service = CacheService()
    fake = _FakeRedis()
    service._client = fake

    service.set_json("results:v1:0:20", {"count": 2}, 30)
    service.set_json("results:v1:20:20", {"count": 3}, 30)
    service.set_json("other:key", {"x": 1}, 30)

    assert service.get_json("results:v1:0:20") == {"count": 2}

    service.delete_prefix("results:v1:")

    assert service.get_json("results:v1:0:20") is None
    assert service.get_json("results:v1:20:20") is None
    assert service.get_json("other:key") == {"x": 1}

    service.close()
    assert fake.closed is True
