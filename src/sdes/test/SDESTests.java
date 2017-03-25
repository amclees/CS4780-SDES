package sdes.test;

import org.junit.Test;

import junit.framework.TestCase;
import sdes.SDES;
import sdes.attack.SDESBruteforce;

public class SDESTests extends TestCase {
  
  @Test
  public void testCasciiUtil() {
    String toEncode = "HELLO, THIS IS A MESSAGE. IS IT, BY CHANCE, ENCODED 'PROPERLY'?";
    byte[][] encoded = SDESBruteforce.encodeCASCII(toEncode.toCharArray());
    String decoded = new String(SDESBruteforce.decodeCASCII(encoded));
    assertTrue(toEncode.equals(decoded));
  }
  
  @Test
  public void testCasciiParse() {
    String toTest = "101100101001101000";
    char[] charToTest = toTest.toCharArray();
    byte[][] parsed = SDESBruteforce.parseCASCII(charToTest);
    byte[][] expected = { { 1, 0, 1, 1, 0 }, { 0, 1, 0, 1, 0 }, { 0, 1, 1, 0, 1 } };
    for(int i = 0; i < expected.length; i++) {
     assertTrue(bitsEqual(parsed[i], expected[i]));
    }
  }
  
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
  public void testSubstitutor() {
    byte[] input = { 1, 0, 0, 1 };
    byte[] expectedOutput = { 1, 0 };
    byte[] output = SDES.substitute(input, SDES.sBox1);
   
    assertEquals(expectedOutput[0], output[0]);
    assertEquals(expectedOutput[1], output[1]);
  }
  
  @Test
  public void testReverser() {
    byte[] input = { 1, 1, 0, 1 };
    byte[] expected = { 1, 0, 1, 1 };
    byte[] reversed = SDESBruteforce.reverse(input);
    assertTrue(bitsEqual(expected, reversed));
  }
  
  @Test
  public void testSwapper() {
    byte[] input = { 1, 0, 0, 1, 1, 1, 1, 0 };
    byte[] expectedOutput = { 1, 1, 1, 0, 1, 0, 0, 1 };
    byte[] output = SDES.swap(input);
    assertTrue(bitsEqual(expectedOutput, output));
  }
  
  @Test
  public void testXor() {
    byte[] input1 = { 1, 0, 0, 1, 1, 0, 1, 0 };
    byte[] input2 = { 0, 0, 1, 0, 1, 1, 0, 0 };
    byte[] expectedOutput = { 1, 0, 1, 1, 0, 1, 1, 0 };
    byte[] output = SDES.xor(input1, input2);
    
    assertTrue(bitsEqual(expectedOutput, output));
  }
  
  @Test
  public void testBitIntConversion() {
    byte[] testBits = { 1, 0, 1, 0 };
    assertEquals(10, SDES.bitsToInt(testBits));
    int a = 2;
    int b = 3;
    byte[] expectedA = { 1, 0 };
    byte[] expectedB = { 1, 1 };
    byte[] doneA = SDES.intToBits(a, 2);
    byte[] doneB = SDES.intToBits(b, 2);
    assertEquals(expectedA[0], doneA[0]);
    assertEquals(expectedA[1], doneA[1]);
    assertEquals(expectedB[0], doneB[0]);
    assertEquals(expectedB[1], doneB[1]);
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
  	byte[] baseArray = { 1, 0, 1, 1 };
  	byte[] left3Array = { 1, 1, 0, 1 };
  	byte[] right2Array = { 1, 1, 1, 0 };
      
  	byte[] leftedArray = SDES.circularShift(baseArray, -3);
 
  	for(int i = 0; i < 4; i++) {
  	  assertEquals(leftedArray[i], left3Array[i]);
  	}
  	
  	for(int i = 0; i < 4; i++) {
      assertEquals(SDES.circularShift(baseArray, 2)[i], right2Array[i]);
    }
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
    
    byte[] ciphertext1 = SDES.Encrypt(key1, plaintext124);
    byte[] ciphertext2 = SDES.Encrypt(key23, plaintext124);
    byte[] ciphertext3 = SDES.Encrypt(key23, plaintext3);
    byte[] ciphertext4 = SDES.Encrypt(key4, plaintext124);
    
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
  
  @Test
  public void testSDESDecryption() {
    byte[] key = { 1, 1, 1, 0, 0, 0, 1, 1, 1, 0 };
    byte[] ciphertext = { 1, 1, 0, 0, 1, 1, 0, 0 };
    byte[] expectedPlaintext = { 1, 0, 1, 0, 1, 0, 1, 0};
    byte[] plaintext = SDES.Decrypt(key, ciphertext);
    
    assertTrue(bitsEqual(expectedPlaintext, plaintext));
  }
  
  public boolean bitsEqual(byte[] b1, byte[] b2) {
    if(b1.length != b2.length) return false;
    for(int i = 0; i < b1.length; i++) {
      if(b1[i] != b2[i]) return false;
    }
    return true;
  }

}
