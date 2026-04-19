// Compile-time debug output gating.
// When NTAG424DEBUG is defined (dev builds), DBG macros compile to Serial output.
// When undefined (production builds), DBG macros compile to nothing — zero overhead.
//
// Usage:
//   Serial.println(F("[bolt] msg"))  →  DBG_PRINTLN(F("[bolt] msg"))
//   Serial.print(F("val="))          →  DBG_PRINT(F("val="))
//   Serial.println(x, HEX)           →  DBG_PRINTLN(x, HEX)
//   Serial.print(data[i], HEX)       →  DBG_PRINT(data[i], HEX)
//
// Keep user-facing command output (help, status, command responses) as plain Serial.print.

#ifndef BOLTY_DEBUG_H
#define BOLTY_DEBUG_H

#include <Arduino.h>

#ifdef NTAG424DEBUG

#define DBG_PRINT(...)    Serial.print(__VA_ARGS__)
#define DBG_PRINTLN(...)  Serial.println(__VA_ARGS__)

#else

#define DBG_PRINT(...)    ((void)0)
#define DBG_PRINTLN(...)  ((void)0)

#endif

#endif
