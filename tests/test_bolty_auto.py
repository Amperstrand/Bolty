#!/usr/bin/env python3
import serial, time, sys, re

PORT = '/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0'
BAUD = 115200

K0 = "11111111111111111111111111111111"
K1 = "22222222222222222222222222222222"
K2 = "33333333333333333333333333333333"
K3 = "44444444444444444444444444444444"
K4 = "55555555555555555555555555555555"
URL = "lnurlw://testcard.local/test?p=00000000000000000000000000000000&c=0000000000000000"

ser = serial.Serial(PORT, BAUD, timeout=1)

def drain(wait=0.5):
    time.sleep(wait)
    raw = b''
    while ser.in_waiting:
        raw += ser.read(ser.in_waiting)
    return raw

def send(cmd, wait=1.5):
    drain(0.3)
    ser.write((cmd + '\n').encode())
    raw = drain(wait)
    text = raw.decode(errors='replace')
    lines = text.strip().split('\n')
    filtered = [l for l in lines if re.search(r'^(\[|Headless|  )', l.strip()) or l.strip().startswith('Job') or l.strip().startswith('LNURL') or 'SUCCESS' in l or 'FAILED' in l or 'error' in l.lower()]
    return '\n'.join(filtered) if filtered else '(no filtered output)'

print("=" * 60)
print("BOLTY CARD PROVISIONING TEST")
print("=" * 60)

print("\n>>> REMOVE card from reader if present")
input("Press ENTER when card is OFF the reader...")

print("\n=== Setting keys ===")
print(send(f"keys {K0} {K1} {K2} {K3} {K4}", 2.0))

print("\n=== Setting URL ===")
print(send(f"url {URL}", 2.0))

print("\n=== Verifying config ===")
print(send("status"))

print("\n" + "=" * 60)
print(">>> PLACE card on reader now")
print("=" * 60)
input("Press ENTER when card is ON the reader...")

print("\n=== Burning card ===")
print(send("burn", 10.0))

print("\n=== Status after burn ===")
print(send("status"))

print("\n" + "=" * 60)
print(">>> Keep card on reader for wipe")
print("=" * 60)
input("Press ENTER to wipe card...")

print("\n=== Wiping card ===")
print(send("wipe", 10.0))

print("\n=== Status after wipe ===")
print(send("status"))

ser.close()
print("\n" + "=" * 60)
print("TEST COMPLETE")
print("=" * 60)
