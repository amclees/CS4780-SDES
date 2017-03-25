package sdes;

import java.util.Arrays;

public class SDES {
  public static final int[] initialKeyPermutation = { 2, 4, 1, 6, 3, 9, 0, 8, 7, 5 };
  public static final int[] keyCompression = { 5, 2, 6, 3, 7, 4, 9, 8 };
  public static final int[] initialPermutation = { 1, 5, 2, 0, 3, 7, 4, 6 };
  public static final int[] finalPermutation = { 3, 0, 2, 4, 6, 1, 7, 5 };
  public static final int[] inExpansion = { 3, 0, 1, 2, 1, 2, 3, 0 };
  public static final int[] outCompression = { 1, 3, 2, 0 };
  public static final int[][] sBox1 = { 
      { 1, 0, 3, 2 },
      { 3, 2, 1, 0 },
      { 0, 2, 1, 3 },
      { 3, 1, 3, 2 }
  };
  public static final int[][] sBox2 = { 
      { 0, 1, 2, 3 },
      { 2, 0, 1, 3 },
      { 3, 0, 1, 0 },
      { 2, 1, 0, 3 }
  };
  
  public static byte[] Encrypt(byte[] rawkey, byte[] plaintext) {
    byte[] permutedPlaintext = permute(plaintext, initialPermutation);
    byte[][] keys = getKeys(rawkey);
    
    byte[] round1Result = swap(mixKey(permutedPlaintext, keys[0]));
    byte[] round2Result = mixKey(round1Result, keys[1]);
    
    byte[] ciphertext = permute(round2Result, finalPermutation);
    
    return ciphertext;
  }
  
  public static byte[] Decrypt(byte[] rawkey, byte[] ciphertext) {
    byte[] permutedCiphertext = permute(ciphertext, initialPermutation);
    byte[][] keys = getKeys(rawkey);
    
    byte[] round1Result = mixKey(permutedCiphertext, keys[1]);
    byte[] round2Result = swap(mixKey(round1Result, keys[0]));
    
    byte[] plaintext = permute(round2Result, finalPermutation);
    
    return plaintext;
  }
  
  public static byte[] mixKey(byte[] input, byte[] key) {
    // fsubk in notes
    byte[][] sides = split(input);
    sides[0] = xor(sides[0], getXorElement(sides[1], key));
    
    return combine(sides[0], sides[1]);
  }
  
  public static byte[] getXorElement(byte[] right, byte[] key) {
    // F(R, SK) in notes
    byte[] expandedAdded = xor(permute(right, inExpansion), key);
    byte[][] sides = split(expandedAdded);
    sides[0] = substitute(sides[0], sBox1);
    sides[1] = substitute(sides[1], sBox2);
    
    return permute(combine(sides[0], sides[1]), outCompression);
  }
  
  public static byte[] swap(byte[] input) {
    byte[][] split = split(input);
    return combine(split[1], split[0]);
  }
  
  public static byte[] xor(byte[] input1, byte[] input2) {
    if(input1.length != input2.length) return null;
    byte[] output = new byte[input1.length];
    for(int i = 0; i < input1.length; i++) {
      if(input1[i] == input2[i]) output[i] = 0;
      else output[i] = 1;
    }
    return output;
  }
  
  public static int bitsToInt(byte[] bits) {
    int value = 0;
    for(int i = 0; i < bits.length; i++) {
      value += bits[i] * Math.pow(2, bits.length - 1 - i);
    }
    return value;
  }
  
  public static byte[] intToBits(int value, int bitsLength) {
    if(value > (Math.pow(2, bitsLength) - 1)) return null;
    byte[] bits = new byte[bitsLength];
    for(int i = 0; i < bits.length; i++) {
      int placeValue = (int)Math.pow(2, bits.length - 1 - i);
      if(value - placeValue < 0) {
        bits[i] = 0;
      } else {
        value -= placeValue;
        bits[i] = 1;
      }
    }
    return bits;
  }
  
  public static byte[] substitute(byte[] input, int[][] sBox) {
    byte[][] split = split(input);
    return intToBits(sBox[bitsToInt(split[0])][bitsToInt(split[1])], 2);
  }

  public static byte[] permute(byte[] input, int[] pBox) {
    byte[] permuted = new byte[pBox.length];
    for(int i = 0; i < pBox.length; i++) {
      permuted[i] = input[pBox[i]];
    }
    return permuted;
  }
  
  public static byte[][] getKeys(byte[] key) {
    byte[][] keys = new byte[2][8];
    byte[] permutedKey = permute(key, initialKeyPermutation);
    
    byte[][] splitKey = split(permutedKey);
    splitKey[0] = circularShift(splitKey[0], -1);
    splitKey[1] = circularShift(splitKey[1], -1);
    byte[] key1 = permute(combine(splitKey[0], splitKey[1]), keyCompression);
    
    splitKey[0] = circularShift(splitKey[0], -2);
    splitKey[1] = circularShift(splitKey[1], -2);
    byte[] key2 = permute(combine(splitKey[0], splitKey[1]), keyCompression);
    
    keys[0] = key1;
    keys[1] = key2;
    return keys;
  }
  
  public static byte[] circularShift(byte[] input, int shifts) {
    byte[] shifted = new byte[input.length];
    
    for(int i = 0; i < input.length; i++) {
      int shiftedPosition = (i + shifts) % input.length;
      if(shiftedPosition < 0) shiftedPosition += input.length;
      shifted[shiftedPosition] = input[i];
    }
    
    return shifted;
  }
  
  public static byte[][] split(byte[] input) {
    byte[][] split = { Arrays.copyOfRange(input, 0, input.length / 2), Arrays.copyOfRange(input, ((input.length / 2)), input.length) };
    return split;
  }
  
  public static byte[] combine(byte[] a, byte[] b) {
    byte[] c = new byte[a.length + b.length];
    
    for(int i = 0; i < c.length; i++) {
      if(i < a.length) c[i] = a[i];
      else c[i] = b[i - a.length];
    }
    
    return c;
  }
}
