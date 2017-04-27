package sdes.test;

import org.junit.Test;

import junit.framework.TestCase;
import sdes.SDES;
import sdes.TripleSDES;
import sdes.attack.SDESBruteforce;

public class SDESTests extends TestCase {
  
  @Test
  public void testTripleSDES() {
    byte[] plaintext = randomGen(8);
    byte[] key1 = randomGen(10);
    byte[] key2 = randomGen(10);
    byte[] ciphertext = TripleSDES.Encrypt(key1, key2, plaintext);
    byte[] decrypted = TripleSDES.Decrypt(key1, key2, ciphertext);
    assertTrue(bitsEqual(plaintext, decrypted));
  }
  
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
  public void testPermutorInvert() { 
    byte[] testInput = { 1, 0, 1, 0, 1, 0, 1, 0 };
    byte[] middle = SDES.permute(testInput, SDES.initialPermutation);
    byte[] output = SDES.permute(middle, SDES.finalPermutation);
    for(int i = 0; i < testInput.length; i++) {
      assertEquals(testInput[i], output[i]);
    }
  }
  
  @Test
  public void testSubstitutor() {
    byte[] input = { 1, 0, 0, 1 };
    byte[] expectedOutput = { 1, 1 }; // Corrected output test
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
    byte[] expectedCiphertext2 = { 1, 1, 0, 0, 1, 0, 1, 0 };
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
    byte[] ciphertext = { 1, 1, 0, 0, 1, 0, 1, 0 };
    byte[] expectedPlaintext = { 1, 0, 1, 0, 1, 0, 1, 0};
    byte[] plaintext = SDES.Decrypt(key, ciphertext);
        
    assertTrue(bitsEqual(expectedPlaintext, plaintext));
  }
  
  @Test
  public void testSDESEncryptDecrypt(){
    int testCount = 8;
    
    for(int i = 0; i < testCount; i++) {
      assertTrue(testSDESende());
    }
  }
  
  public boolean testSDESende(){
    byte[] key = randomGen(10);
    byte[] plaintext = randomGen(8);
    byte[] ciphertext = SDES.Encrypt(key, plaintext);
    byte[] result = SDES.Decrypt(key, ciphertext);
    return bitsEqual(plaintext,result);
  }
  
  public byte[] randomGen(int ranSize){
    byte[] output = new byte[ranSize];
    for(int i = 0; i < output.length; i++)
      output[i] = (byte)(Math.random()*2);
    return output;
  }
  
  @Test
  public void testSDESLongForm() {
    System.out.println("Long Form Encryption Test:");
    byte[] key = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
    byte[] plaintext = { 1, 0, 1, 0, 1, 0, 1, 0 };
    System.out.print("Plain: ");
    printArray(plaintext);
    
    byte[] initperm = SDES.permute(plaintext, SDES.initialPermutation);
    System.out.print("IPerm: ");
    printArray(initperm);
    
    byte[][] keys = SDES.getKeys(key);
    System.out.print("Keys0: ");
    printArray(keys[0]);
    System.out.print("Keys1: ");
    printArray(keys[1]);
    
    byte[] round1Result = SDES.mixKey(initperm, keys[0]);
    System.out.print("Rnd1R: ");
    printArray(round1Result);
    
    byte[] rnd1swp = SDES.swap(round1Result);
    System.out.print("Rnd1S: ");
    printArray(rnd1swp);
    
    byte[] round2Result = SDES.mixKey(rnd1swp, keys[1]);
    System.out.print("Rnd2R: ");
    printArray(round2Result);
    
    byte[] ciphertext = SDES.permute(round2Result, SDES.finalPermutation);
    System.out.print("Ciphr: ");
    printArray(ciphertext);
    
    byte[] expectedCiphertext = { 0, 0, 0, 0, 0, 1, 0, 0 };
    assertTrue(bitsEqual(expectedCiphertext,ciphertext));
    System.out.println();
  }
  
    /*
      Table being tested:
      1 0000000000     00000000     ?
      2 1111111111     11111111     ?
      3 0000011111     00000000     ?
      4 0000011111     11111111     ?
      5 1000101110     ?            00011100
      6 1000101110     ?            11000010
      7 0010011111     ?            10011101
      8 0010011111     ?            10010000
    */
  @Test
  public void testSDESresults(){
    byte[] key1  = {0,0,0,0,0,0,0,0,0,0};
    byte[] key2  = {1,1,1,1,1,1,1,1,1,1};
    byte[] key34 = {0,0,0,0,0,1,1,1,1,1};
    byte[] key56 = {1,0,0,0,1,0,1,1,1,0};
    byte[] key78 = {0,0,1,0,0,1,1,1,1,1};
    
    byte[] plaintext13 = {0,0,0,0,0,0,0,0};
    byte[] plaintext24 = {1,1,1,1,1,1,1,1};
    
    byte[] ciphertext5 = {0,0,0,1,1,1,0,0};
    byte[] ciphertext6 = {1,1,0,0,0,0,1,0};
    byte[] ciphertext7 = {1,0,0,1,1,1,0,1};
    byte[] ciphertext8 = {1,0,0,1,0,0,0,0};
    
    System.out.println("Raw Key\t\tPlaintext\tCiphertext");
    printTableRow(key1, plaintext13, SDES.Encrypt(key1, plaintext13));
    printTableRow(key2, plaintext24, SDES.Encrypt(key2, plaintext24));
    printTableRow(key34, plaintext13, SDES.Encrypt(key34, plaintext13));
    printTableRow(key34, plaintext24, SDES.Encrypt(key34, plaintext24));
    printTableRow(key56, SDES.Decrypt(key56, ciphertext5), ciphertext5);
    printTableRow(key56, SDES.Decrypt(key56, ciphertext6), ciphertext6);
    printTableRow(key78, SDES.Decrypt(key78, ciphertext7), ciphertext7);
    printTableRow(key78, SDES.Decrypt(key78, ciphertext8), ciphertext8);
    System.out.println("");
  }
  
  /*
    Table being tested:
    1 0000000000     0000000000     00000000     ?
    2 1000101110     0110101110     11010111     ?
    3 1000101110     0110101110     10101010     ?
    4 1111111111     1111111111     10101010     ?
    5 1000101110     0110101110     ?            11100110
    6 1011101111     0110101110     ?            01010000
    7 0000000000     0000000000     ?            10000000
    8 1111111111     1111111111     ?            10010010
  */
  
  @Test
  public void testTripleSDESresults(){
    byte[] keya17b17 = {0,0,0,0,0,0,0,0,0,0};
    byte[] keya235   = {1,0,0,0,1,0,1,1,1,0};
    byte[] keyb2356  = {0,1,1,0,1,0,1,1,1,0};
    byte[] keya48b48 = {1,1,1,1,1,1,1,1,1,1};
    byte[] keya6     = {1,0,1,1,1,0,1,1,1,1};
    
    byte[] plaintext1  = {0,0,0,0,0,0,0,0};
    byte[] plaintext2  = {1,1,0,1,0,1,1,1};
    byte[] plaintext34 = {1,0,1,0,1,0,1,0};
    
    byte[] ciphertext5 = {1,1,1,0,0,1,1,0};
    byte[] ciphertext6 = {0,1,0,1,0,0,0,0};
    byte[] ciphertext7 = {1,0,0,0,0,0,0,0};
    byte[] ciphertext8 = {1,0,0,1,0,0,1,0};
    
    System.out.println("Raw Key A\tRaw Key B\tPlaintext\tCiphertext");
    printTableRow(keya17b17,keya17b17,plaintext1,TripleSDES.Encrypt(keya17b17,keya17b17,plaintext1));
    printTableRow(keya235,keyb2356,plaintext2,TripleSDES.Encrypt(keya235,keyb2356,plaintext2));
    printTableRow(keya235,keyb2356,plaintext34,TripleSDES.Encrypt(keya235,keyb2356,plaintext34));
    printTableRow(keya48b48,keya48b48,plaintext34,TripleSDES.Encrypt(keya48b48,keya48b48,plaintext34));
    printTableRow(keya235,keyb2356,TripleSDES.Decrypt(keya235,keyb2356,ciphertext5),ciphertext5);
    printTableRow(keya6,keyb2356,TripleSDES.Decrypt(keya6,keyb2356,ciphertext6),ciphertext6);
    printTableRow(keya17b17,keya17b17,TripleSDES.Decrypt(keya17b17,keya17b17,ciphertext7),ciphertext7);
    printTableRow(keya48b48,keya48b48,TripleSDES.Decrypt(keya48b48,keya48b48,ciphertext8),ciphertext8);
    System.out.println();
  }
  
  public boolean bitsEqual(byte[] b1, byte[] b2) {
    if (b1.length != b2.length) {
      return false;
    }
    for (int i = 0; i < b1.length; i++) {
      if (b1[i] != b2[i]) {
        return false;
      }
    }
    return true;
  }
  
  public void printArray(byte[] input){
    for (int i = 0; i < input.length; i++) {
      System.out.print(input[i]);
    }
    System.out.println("");
  }
  
  public void printArrayNoLn(byte[] input){
    for (int i = 0; i < input.length; i++) {
      System.out.print(input[i]);
    }
  }
  
  public void printTableRow(byte[] ... arrays){
    for (byte[] b : arrays) {
      printArrayNoLn(b);
      System.out.print("\t");
    }
    System.out.println("");
  }
}
