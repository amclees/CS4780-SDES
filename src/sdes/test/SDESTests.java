package sdes.test;

import org.junit.Test;

import junit.framework.TestCase;
import sdes.SDES;

public class SDESTests extends TestCase {
  
  @Test
  public void testPermutor() { 
    byte[] testInput = { 1, 0, 1, 0, 1 };
    int[] testPBox = { 0, 3, 2 };
    byte[] expected = { 1, 0, 1 };
    byte[] output = SDES.permute(testInput, testPBox);
    for(int i = 0; i < expected.length; i++) {
      assertEquals(expected[i], output[i]);
    }
  }
  
  @Test
  public void testKeyGenerator() {
    byte[] inputKey = { 1, 0, 1, 0, 0, 0, 0, 0, 1, 0 };
    byte[][] roundKeys = SDES.getKeys(inputKey);
    
    byte[] expectedKey1 = { 1, 0, 1, 0, 0, 1, 0, 0 };
    byte[] expectedKey2 = { 0, 1, 0, 0, 0, 0, 1, 1 };
    
    for(int i = 0; i < expectedKey1.length; i++) {
      assertEquals(expectedKey1[i], roundKeys[0][i]);
    }
    for(int i = 0; i < expectedKey2.length; i++) {
      assertEquals(expectedKey2[i], roundKeys[1][i]);
    }
  }
  
  @Test
  public void testCircularShift() {
    assertEquals(0, 1);
  }
  
  @Test
  public void testSDESEncryption() {
    byte[] key1 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    byte[] key23 = { 1, 1, 1, 0, 0, 0, 1, 1, 1, 0 };
    byte[] key4 = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
    
    byte[] plaintext124 = { 1, 0, 1, 0, 1, 0, 1, 0};
    byte[] plaintext3 = { 0, 1, 0, 1, 0, 1, 0, 1 };
    
    byte[] expectedCiphertext1 = { 0, 0, 0, 1, 0, 0, 0, 1 };
    byte[] expectedCiphertext2 = { 1, 1, 0, 0, 1, 1, 0, 0 };
    byte[] expectedCiphertext3 = { 0, 1, 1, 1, 0, 0, 0, 0 };
    byte[] expectedCiphertext4 = { 0, 0, 0, 0, 0, 1, 0, 0 };
    
    byte[] ciphertext1 = SDES.Encrypt(plaintext124, key1);
    byte[] ciphertext2 = SDES.Encrypt(plaintext124, key23);
    byte[] ciphertext3 = SDES.Encrypt(plaintext3, key23);
    byte[] ciphertext4 = SDES.Encrypt(plaintext124, key4);
    
    for(int i = 0; i < ciphertext1.length; i++) {
      assertEquals(ciphertext1[i], expectedCiphertext1[i]);
    }
    for(int i = 0; i < ciphertext2.length; i++) {
      assertEquals(ciphertext2[i], expectedCiphertext2[i]);
    }
    for(int i = 0; i < ciphertext3.length; i++) {
      assertEquals(ciphertext3[i], expectedCiphertext3[i]);
    }
    for(int i = 0; i < ciphertext4.length; i++) {
      assertEquals(ciphertext4[i], expectedCiphertext4[i]);
    }
  }
  
}