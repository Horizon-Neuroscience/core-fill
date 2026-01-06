import dramatiq
from dramatiq.results.backends import RedisBackend
from dramatiq.brokers.redis import RedisBroker
from dramatiq.results import Results

_broker_ready = False
_broker = None
_result_backend = None


def ensure_broker(
    redis_host: str = "localhost",
    redis_port: int = 6379,
    redis_db: int = 0
):
    """
    Initialize the Dramatiq broker with Redis backend.

    Args:
        redis_host: Redis server hostname
        redis_port: Redis server port
        redis_db: Redis database number
    """
    global _broker_ready, _result_backend, _broker
    if not _broker_ready:
        redis_broker = RedisBroker(host=redis_host, port=redis_port, db=redis_db)
        _result_backend = RedisBackend(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            namespace="results"
        )
        redis_broker.add_middleware(Results(backend=_result_backend))
        _broker = redis_broker
        dramatiq.set_broker(_broker)
        _broker_ready = True


def get_result_backend():
    return _result_backend


def get_broker():
    return _broker
