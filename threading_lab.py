import threading
import time


def hello():
    time.sleep(3)
    print("Hello from a thread!")


print("Before creating thread:")
print(threading.active_count())

t1 = threading.Thread(target=hello)

t1.start()

print("After starting thread:")
print(threading.active_count())
