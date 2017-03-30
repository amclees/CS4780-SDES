package sdes.attack;

import java.util.PriorityQueue;
import java.util.Queue;
import java.util.Scanner;
import java.util.Stack;

import sdes.SDES;
import sdes.TripleSDES;
import sdes.attack.TripleSDESBruteforce.Possibility;

public class SDESBruteforce {
  
  public static void main(String[] args) {
    Scanner sc = new Scanner(System.in);
    System.out.printf("Enter:%n  1 for CASCII Encryption%n  2 for CASCII SDES Bruteforce%n  See other file for TripleSDES bruteforce%n");
    int choice = -1;
    try {
      choice = sc.nextInt(); 
    } catch(Exception e) {}
    switch(choice) {
      case 1: CASCIIEncryption(sc); break;
      case 2: attackSDES(sc); break;
      default: System.out.println("Invalid choice, quitting.");
    }
  }
  
  public static void CASCIIEncryption(Scanner sc) {
    System.out.println("Enter the bit representation of your key (10 bits):");
    char[] input = sc.next().toCharArray();
    if(input.length != 10) {
      System.out.println("Invalid key length, quitting.");
      return;
    }
    byte[] key = new byte[input.length];
    for(int i = 0; i < input.length; i++) {
      if(input[i] == '0') key[i] = 0;
      else if(input[i] == '1') key[i] = 1;
      else {
        System.out.println("Invalid key, quitting.");
        return;
      }
    }
    
    sc.nextLine();
    System.out.println("Enter your plaintext in CASCII:");
    char[] plaintext = sc.nextLine().toUpperCase().toCharArray();
    
    byte[][] encoded = encodeCASCII(plaintext);
    byte[] toEncrypt = padCASCII(encoded);
    System.out.println("Your padded plaintext is:\n" + bitsToString(toEncrypt));
    byte[][] toEncryptBlocks = blockify(toEncrypt, 8);
    byte[][] ciphertextBlocks = SDES.encryptBlocks(key, toEncryptBlocks);
    byte[] ciphertext = flatten(ciphertextBlocks);
    
    System.out.println("Your ciphertext is:");
    System.out.println(bitsToString(ciphertext));
    
    System.out.println("Your decrypted plaintext is:");
    System.out.println(bitsToString(flatten(SDES.decryptBlocks(key, ciphertextBlocks))));
    byte[] flatDecryptedPlaintext = flatten(SDES.decryptBlocks(key, ciphertextBlocks));
    char[] decodedPlaintext = decodeCASCII(blockify(flatDecryptedPlaintext, 5));
    System.out.println(new String(decodedPlaintext));
  }
  
  public static void attackSDES(Scanner sc) {
    System.out.println("Please enter your ciphertext bits:");
    byte[] ciphertext = parseBits(sc.next().toCharArray());
    byte[][] ciphertextBlocks = blockify(ciphertext, 8);
    Queue<Possibility> possible = new PriorityQueue<Possibility>();
    for(int i = 0; i < 1024; i++) {
      byte[] key = SDES.intToBits(i, 10);
      byte[] decryptedPotential = SDESBruteforce.flatten(SDES.decryptBlocks(key, ciphertextBlocks));
      String potentialPlaintext = new String(SDESBruteforce.decodeCASCII(SDESBruteforce.blockify(decryptedPotential, 5)));
      Possibility currentPossibility = new Possibility(potentialPlaintext, key);
      possible.add(currentPossibility);
    }
    for(int i = 0; i < 12; i++) {
      System.out.println(possible.poll());
    }
  }
  
  public static class Possibility implements Comparable<Possibility> {
    public String plaintext;
    public byte[] key;
    public int score;
    
    public Possibility(String plaintext, byte[] key) {
     this.plaintext = plaintext; 
     this.key = key;
     int eCount = plaintext.length() - plaintext.replace("E", "").length();
     int spaceCount = plaintext.length() - plaintext.replace(" ", "").length();
     int thCount = plaintext.length() - plaintext.replace("TH", "").length();
     int punctuationCount = 0;
     punctuationCount += plaintext.length() - plaintext.replace(",", "").length();
     punctuationCount += plaintext.length() - plaintext.replace(":", "").length();
     punctuationCount += plaintext.length() - plaintext.replace("?", "").length();
     punctuationCount += plaintext.length() - plaintext.replace(".", "").length();
     
     score = eCount + thCount + spaceCount - punctuationCount;
    }

    @Override
    public int compareTo(Possibility other) {
       return other.score - this.score;
    }
    
    public String toString() { 
      return "Score: " + score + " Key: (" + SDESBruteforce.bitsToString(key) + ") Plaintext: " + plaintext;
    }
  }
  
  public static byte[] padCASCII(byte[][] encodedCASCII) {
    int padding = (8 - ((encodedCASCII.length * 5) % 8)) % 8;
    byte[] padded = new byte[padding + (encodedCASCII.length * 5)];
    for(int i = 0; i < encodedCASCII.length; i++) {
      for(int j = 0; j < 5; j++) {
        padded[(i * 5) + j] = encodedCASCII[i][j];
      }
    }
    
    for(int i = padded.length - padding; i < padded.length; i++) {
      padded[i] = 0;
    }
    return padded;
  }
  
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
  
  public static byte[] parseBits(char[] bits) {
    byte[] parsed = new byte[bits.length];
    for(int i = 0; i < bits.length; i++) {
      if(bits[i] == '0') parsed[i] = 0;
      else if(bits[i] == '1') parsed[i] = 1;
      else return null;
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
  
  public static byte[] flatten(byte[][] square) {
    int rowLength = square[0].length;
    byte[] flat = new byte[rowLength * square.length];
    for(int i = 0; i < flat.length; i++) {
      flat[i] = square[i / rowLength][i % rowLength];
    }
    return flat;
  }
  
  public static byte[][] blockify(byte[] flat, int blockSize) {
    int padding = flat.length % blockSize;//(blockSize - (flat.length % blockSize)) % blockSize; // 4
    int rows = flat.length / blockSize;// + (padding == 0 ? 0 : 1); // 3 + 1
    byte[][] blocks = new byte[rows][blockSize];
    for(int i = 0; i < flat.length - padding; i++) {
      blocks[i / blockSize][i % blockSize] = flat[i];
    }
    return blocks;
  }
  
  public static String bitsToString(byte[] bits) {
    char[] chars = new char[bits.length];
    for(int i = 0; i < chars.length; i++) {
      chars[i] = bits[i] == 1 ? '1' : '0';
    }
    return new String(chars);
  }
 
}
