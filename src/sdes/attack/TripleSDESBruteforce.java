package sdes.attack;

import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.Scanner;
import java.util.concurrent.PriorityBlockingQueue;

import sdes.SDES;
import sdes.TripleSDES;

public class TripleSDESBruteforce {
  
  public static void main(String[] args) throws InterruptedException {
    Scanner sc = new Scanner(System.in);
    System.out.println("Enter your TripleDES encrypted CASCII encoded ciphertext:");
    byte[] ciphertext = SDESBruteforce.parseBits(sc.next().toCharArray());
    long startTime = System.currentTimeMillis();
    byte[][] ciphertextBlocks = SDESBruteforce.blockify(ciphertext, 8);
    Queue<Possibility> possible = new PriorityBlockingQueue<>();
    List<Thread> threads = new ArrayList<>(1024);
    
    for(int i = 0; i < 1024; i++) {
      byte[] key1 = SDES.intToBits(i, 10);
      Thread keyThread = (new Thread() {
        @Override
        public void run() {
          for(int j = 0; j < 1024; j++) {
            byte[] key2 = SDES.intToBits(j, 10);
            byte[] decryptedPotential = SDESBruteforce.flatten(TripleSDES.decryptBlocks(key1, key2, ciphertextBlocks));
            String potentialPlaintext = new String(SDESBruteforce.decodeCASCII(SDESBruteforce.blockify(decryptedPotential, 5)));
            Possibility currentPossibility = new Possibility(potentialPlaintext, key1, key2);
            possible.add(currentPossibility);
          } 
        }
      });
      threads.add(keyThread);
      keyThread.start();
    }
    
    boolean stay = true;
    while(stay) {
      stay = false;
      for(int i = 0; i < threads.size(); i++) {
        Thread keyThread = threads.get(i);
        if(keyThread.isAlive()) stay = true;
        else threads.remove(keyThread);
      }
      Thread.sleep(1500);
    }
    
    for(int i = 0; i < 12; i++) {
      System.out.println(possible.poll());
    }
    
    long elapsed = System.currentTimeMillis() - startTime;
    System.out.printf("%dms elapsed during bruteforce%n", elapsed);
    sc.close();
  }
  
  public static class Possibility implements Comparable<Possibility> {
    public String plaintext;
    public byte[] key1;
    public byte[] key2;
    public int score;
    
    public Possibility(String plaintext, byte[] key1, byte[] key2) {
     this.plaintext = plaintext; 
     this.key1 = key1;
     this.key2 = key2;
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
    
    @Override
    public boolean equals(Object other) {
      return other == this;
    }
    
    @Override
    public int hashCode() {
      return plaintext.hashCode();
    }
    
    public String toString() { 
      return "Score: " + score + " Key 1: (" + SDESBruteforce.bitsToString(key1) + ") Key 2: (" + SDESBruteforce.bitsToString(key2) + ") Plaintext: " + plaintext;
    }
  }
}