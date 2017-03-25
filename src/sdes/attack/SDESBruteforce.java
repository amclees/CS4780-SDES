package sdes.attack;

import sdes.SDES;

public class SDESBruteforce {
  public static byte[][] encodeCASCII(char[] chars) {
    byte[][] encoded = new byte[chars.length][5];
    for(int i = 0; i < chars.length; i++) {
      int asciiValue = (int)chars[i];
      int casciiValue = -1;
      switch(asciiValue) {
        case 32: casciiValue = 0; break; // space
        case 44: casciiValue = 27; break; // ,
        case 63: casciiValue = 28; break; // ?
        case 58: casciiValue = 29; break; // :
        case 46: casciiValue = 30; break; // .
        case 39: casciiValue = 31; break; // ' Note that this may cause issues if users use ` instead of '
        default: casciiValue = asciiValue - 64; break;
      }
      if(casciiValue < 0 || casciiValue > 31) return null;
      byte[] codedByte = reverse(SDES.intToBits(casciiValue, 5));
      encoded[i] = codedByte;
    }
    return encoded;
  }
  
  public static char[] decodeCASCII(byte[][] encoded) {
    char[] chars = new char[encoded.length];
    for(int i = 0; i < encoded.length; i++) {
      int casciiValue = SDES.bitsToInt(reverse(encoded[i]));
      if(casciiValue < 0 || casciiValue > 31) return null;
      int asciiValue;
      switch(casciiValue) {
        case 0: asciiValue = 32; break; // space
        case 27: asciiValue = 44; break; // ,
        case 28: asciiValue = 63; break; // ?
        case 29: asciiValue = 58; break; // :
        case 30: asciiValue = 46; break; // .
        case 31: asciiValue = 39; break; // '
        default: asciiValue = casciiValue + 64; break;
      }
      chars[i] = (char)asciiValue;
    }
    return chars;
  }
  
  public static byte[][] parseCASCII(char[] toParse) {
    int padded = toParse.length % 5;
    byte[][] parsed = new byte[(toParse.length - padded) / 5][5];
    int currentByte = 0;
    for(int i = 0; i < toParse.length - padded; i += 5) {
      int totalValue = 0;
      for(int j = i; j < i + 5; j++) {
       int placeValue = toParse[j] == '0' ? 0 : 1;
       totalValue += placeValue * Math.pow(2, i + 4 - j); 
      }
      parsed[currentByte++] = SDES.intToBits(totalValue, 5);
    }
    return parsed;
  }
  
  /* 
   * This is necessary due to the "endianness" of CASCII. 
   * Endianness usually refers to bytes, but means bits in this context. 
  */
  public static byte[] reverse(byte[] input) {
    byte[] reversed = new byte[input.length];
    for(int i = 0; i < input.length; i++) {
      reversed[i] = input[input.length - 1 - i];
    }
    return reversed;
  }
}