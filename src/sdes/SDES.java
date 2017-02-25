package sdes;

import java.util.Arrays;

public class SDES {
  public static final int[] initialKeyPermutation = { 2, 4, 1, 6, 3, 9, 0, 8, 7, 5 };
  public static final int[] keyCompression = { 5, 2, 6, 3, 7, 4, 9, 8 };
  public static final int[] initialPermutation = { 1, 5, 2, 0, 3, 7, 4, 6 };
  public static final int[] finalPermutation = { 3, 0, 2, 4, 6, 1, 7, 5 };
  public static final int[] inExpansion = { 3, 0, 1, 2, 1, 2, 3, 0 };
  public static final int[] outCompression = { 1, 3, 2, 0 };
  
  public static byte[] Encrypt(byte[] rawkey, byte[] plaintext) {
    return null;
  }
  
  public static byte[] Decrypt(byte[] rawkey, byte[] ciphertext) {
    return null;
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
    
    for(int i = 0; i < input.length - 1; i++) {
      int shiftedPosition = (i + shifts) % input.length;
      if(shiftedPosition < 0) shiftedPosition += input.length;
      shifted[i] = input[shiftedPosition];
    }

    return shifted;
  }
  
  public static byte[][] split(byte[] input) {
    byte[][] split = { Arrays.copyOfRange(input, 0, input.length / 2), Arrays.copyOfRange(input, ((input.length / 2)), input.length) };
    return split;
  }
  
  public static byte[] combine(byte[] a, byte[] b) {
    byte[] c = new byte[a.length + b.length];
    int j = 0;
    int k = 0;
    for(int i = 0; i < c.length; i++) {
      try {
        if(a[j] < b[k]) {
          c[i] = a[j];
          j++;
          continue;
        } 
      } catch(IndexOutOfBoundsException ex) {}
      try {
      if(a[j] > b[k]) {
        c[i] = b[k];
        k++;
        continue;
      }
      } catch(IndexOutOfBoundsException ex) {}
      if(j < a.length) {
        c[i] = a[j];
        j++;
      } else {
        c[i] = b[k];
        k++;
      }
    }
    return c;
  }
}
