/*
 * Dump the OPTIGA Trust M Coprocessor UID (OID 0xE0C2) on a repeating loop
 * so the host can catch it regardless of when it opens the CDC port.
 */

#include "OPTIGATrustM.h"

#define UID_LENGTH 27

static bool ready = false;

void setup()
{
  Serial.begin(115200);
  delay(1000);
}

static void printHex(const uint8_t* buf, uint16_t len)
{
  for (uint16_t i = 0; i < len; i++) {
    if (buf[i] < 0x10) Serial.print('0');
    Serial.print(buf[i], HEX);
  }
}

void loop()
{
  if (!ready) {
    Serial.println("BEGIN");
    if (trustM.begin()) {
      Serial.println("ERR begin");
      delay(2000);
      return;
    }
    trustM.setCurrentLimit(15);
    ready = true;
    Serial.println("OK begin");
  }

  uint8_t  uid[UID_LENGTH];
  uint16_t uidLength = UID_LENGTH;

  if (trustM.getUniqueID(uid, uidLength)) {
    Serial.println("ERR uid");
  } else {
    Serial.print("UID ");
    Serial.print(uidLength);
    Serial.print(" ");
    printHex(uid, uidLength);
    Serial.println();
  }

  delay(2000);
}
