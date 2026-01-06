from dramatiq.message import Message
from broker import ensure_broker, get_broker

# MAKE SURE YOU CAN CONNECT TO REDIS FROM LOCAL
# Initialize broker on module import
ensure_broker(redis_host="10.94.93.243", redis_port=6379, redis_db=0)

def enqueue(actor_name: str, queue_name: str, *, args=(), kwargs=None, options=None) -> Message:
    kwargs = kwargs or {}
    options = options or {}
    msg = Message(
        queue_name=queue_name,
        actor_name=actor_name,
        args=args,
        kwargs=kwargs,
        options=options,
    )
    get_broker().enqueue(msg)
    return msg

def make_msg_stub(actor_name: str, queue_name: str, message_id: str) -> Message:
    return Message(
        queue_name=queue_name,
        actor_name=actor_name,
        args=(),
        kwargs={},
        options={},
        message_id=message_id,
    )
